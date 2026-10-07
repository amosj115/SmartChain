import hashlib
import json
import math
import re
import uuid
from datetime import date

from flask import Blueprint, abort, current_app, jsonify, render_template, request
from flask_login import current_user, login_required

from .extensions import db
from .models import AuditLog, IntegrationConnection, IntegrationTransaction


integration_bp = Blueprint("integrations", __name__)

CONNECTORS = {
    "twf": {"name": "Travel With Flair", "source_of_truth": "TWF for booking execution", "operations": {"create_travel_request", "get_travel_request_status"}},
    "csd": {"name": "Central Supplier Database", "source_of_truth": "CSD for supplier master data", "operations": {"validate_supplier"}},
    "etender": {"name": "National Treasury eTender", "source_of_truth": "eTender for publication", "operations": {"publish_tender"}},
    "finance": {"name": "Finance / BAS", "source_of_truth": "Authoritative departmental finance system", "operations": {"check_budget"}},
    "smartgov": {"name": "SmartGov", "source_of_truth": "Authorised SmartGov service", "operations": {"submit_record_metadata"}},
    "smartfleet": {"name": "SmartFleet", "source_of_truth": "SmartChain SmartFleet", "operations": set()},
    "rq": {"name": "RQ & Procurement", "source_of_truth": "SmartChain RQ", "operations": set()},
    "tender": {"name": "Tender Management", "source_of_truth": "SmartChain Tender", "operations": set()},
    "contracts": {"name": "Contract Management", "source_of_truth": "SmartChain Contracts", "operations": set()},
    "command-centre": {"name": "Command Centre", "source_of_truth": "SmartChain Command Centre", "operations": set()},
}

REQUIRED_FIELDS = {
    ("twf", "create_travel_request"): {"case_id", "request_id", "destination", "travel_date"},
    ("twf", "get_travel_request_status"): {"provider_reference"},
    ("csd", "validate_supplier"): {"csd_supplier_number"},
    ("etender", "publish_tender"): {"case_id", "tender_number", "title", "closing_date"},
    ("finance", "check_budget"): {"case_id", "cost_centre", "amount"},
    ("smartgov", "submit_record_metadata"): {"case_id", "record_reference", "document_hash"},
}

ALLOWED_FIELDS = {
    ("twf", "create_travel_request"): {"case_id", "request_id", "destination", "travel_date"},
    ("twf", "get_travel_request_status"): {"case_id", "provider_reference"},
    ("csd", "validate_supplier"): {"case_id", "csd_supplier_number"},
    ("etender", "publish_tender"): {"case_id", "tender_number", "title", "closing_date"},
    ("finance", "check_budget"): {"case_id", "cost_centre", "amount"},
    ("smartgov", "submit_record_metadata"): {"case_id", "record_reference", "document_hash"},
}


class IntegrationRequestError(ValueError):
    pass


class IdempotencyConflict(ValueError):
    pass


def ensure_default_connections():
    for key, details in CONNECTORS.items():
        if not IntegrationConnection.query.filter_by(key=key).first():
            is_native = key in {"smartfleet", "rq", "tender", "contracts", "command-centre"}
            db.session.add(IntegrationConnection(
                key=key,
                name=details["name"],
                mode="INTERNAL" if is_native else "SANDBOX",
                status="INTERNAL" if is_native else "SANDBOX",
                source_of_truth=details["source_of_truth"],
            ))
    db.session.commit()


def _canonical_json(payload):
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _digest(value):
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _sandbox_response(connector, operation, payload, idempotency_key):
    reference = f"SBX-{_digest(idempotency_key)[:12].upper()}"
    case_id = payload.get("case_id")
    if connector == "twf" and operation == "create_travel_request":
        return {"environment": "SANDBOX", "authoritative": False, "status": "SANDBOX_PENDING", "provider_reference": reference, "case_id": case_id}
    if connector == "twf" and operation == "get_travel_request_status":
        return {"environment": "SANDBOX", "authoritative": False, "status": "SANDBOX_PENDING", "provider_reference": payload["provider_reference"]}
    if connector == "csd":
        return {"environment": "SANDBOX", "authoritative": False, "status": "SANDBOX_NOT_VERIFIED", "csd_supplier_number": payload["csd_supplier_number"]}
    if connector == "etender":
        return {"environment": "SANDBOX", "authoritative": False, "status": "SANDBOX_PUBLICATION_SIMULATED", "publication_reference": reference, "tender_number": payload["tender_number"]}
    if connector == "finance":
        return {"environment": "SANDBOX", "authoritative": False, "status": "SANDBOX_NOT_CHECKED", "case_id": case_id}
    if connector == "smartgov":
        return {"environment": "SANDBOX", "authoritative": False, "status": "SANDBOX_METADATA_ACCEPTED", "record_reference": payload["record_reference"], "case_id": case_id}
    raise IntegrationRequestError("This connector operation is not available.")


def execute_sandbox(connector, operation, payload, idempotency_key, actor):
    if connector not in CONNECTORS or operation not in CONNECTORS[connector]["operations"]:
        raise IntegrationRequestError("Connector operation is not supported.")
    if not isinstance(payload, dict):
        raise IntegrationRequestError("Request payload must be a JSON object.")
    if not isinstance(idempotency_key, str) or not idempotency_key.strip() or len(idempotency_key) > 200:
        raise IntegrationRequestError("A non-empty idempotency key of at most 200 characters is required.")
    missing = REQUIRED_FIELDS[(connector, operation)] - payload.keys()
    if missing:
        raise IntegrationRequestError(f"Missing required fields: {', '.join(sorted(missing))}.")
    unexpected = payload.keys() - ALLOWED_FIELDS[(connector, operation)]
    if unexpected:
        raise IntegrationRequestError(f"Unapproved fields: {', '.join(sorted(unexpected))}.")
    for field, value in payload.items():
        if field == "amount":
            if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value < 0:
                raise IntegrationRequestError("amount must be a finite, non-negative number.")
        elif not isinstance(value, str) or not value.strip():
            raise IntegrationRequestError(f"{field} must be a non-empty string.")
    if "travel_date" in payload or "closing_date" in payload:
        date_field = "travel_date" if "travel_date" in payload else "closing_date"
        try:
            date.fromisoformat(payload[date_field])
        except ValueError as error:
            raise IntegrationRequestError(f"{date_field} must use YYYY-MM-DD format.") from error
    if "document_hash" in payload and not re.fullmatch(r"[0-9a-fA-F]{64}", payload["document_hash"]):
        raise IntegrationRequestError("document_hash must be a SHA-256 hexadecimal digest.")

    request_json = _canonical_json(payload)
    request_hash = _digest(request_json)
    existing = IntegrationTransaction.query.filter_by(idempotency_key=idempotency_key).first()
    if existing:
        if existing.request_hash != request_hash or existing.target_system != connector or existing.operation != operation:
            raise IdempotencyConflict("This idempotency key was already used with a different request.")
        return existing, False

    connection = IntegrationConnection.query.filter_by(key=connector).one()
    transaction = IntegrationTransaction(
        transaction_id="PENDING",
        correlation_id=str(payload.get("case_id") or uuid.uuid4()),
        idempotency_key=idempotency_key,
        case_id=payload.get("case_id"),
        connection=connection,
        source_system="SMARTCHAIN",
        target_system=connector,
        operation=operation,
        status="PROCESSING",
        request_payload=request_json,
        request_hash=request_hash,
        actor=actor,
    )
    db.session.add(transaction)
    try:
        db.session.flush()
        transaction.transaction_id = f"INT-{transaction.id:09d}"
        response = _sandbox_response(connector, operation, payload, idempotency_key)
        response_json = _canonical_json(response)
        transaction.response_payload = response_json
        transaction.response_hash = _digest(response_json)
        transaction.status = "SANDBOX_COMPLETED"
        db.session.add(AuditLog(
            module="Integration Hub",
            action="sandbox_transaction",
            entity="integration_transaction",
            details=f"{transaction.transaction_id} {connector}.{operation} {transaction.status}; correlation={transaction.correlation_id}; request_sha256={request_hash}; response_sha256={transaction.response_hash}",
            user_id=actor.id if actor else None,
        ))
        db.session.commit()
    except Exception:
        db.session.rollback()
        raise
    return transaction, True


def _may_view():
    return current_user.is_authenticated and current_user.role_obj and any(
        permission.name == "integration.view" for permission in current_user.role_obj.permissions
    )


def _require_view():
    if not _may_view():
        abort(403)


def _require_test():
    role_name = current_user.role_obj.name if current_user.is_authenticated and current_user.role_obj else None
    if role_name != "System Administrator":
        abort(403)


def _transaction_json(item):
    return {
        "transaction_id": item.transaction_id,
        "correlation_id": item.correlation_id,
        "idempotency_key": item.idempotency_key,
        "case_id": item.case_id,
        "source_system": item.source_system,
        "target_system": item.target_system,
        "operation": item.operation,
        "status": item.status,
        "request_hash": item.request_hash,
        "response_hash": item.response_hash,
        "request": json.loads(item.request_payload),
        "response": json.loads(item.response_payload) if item.response_payload else None,
        "error_code": item.error_code,
        "created_at": item.created_at.isoformat() if item.created_at else None,
    }


@integration_bp.route("/integrations", methods=["GET", "POST"])
@login_required
def hub():
    _require_view()
    result = None
    if request.method == "POST":
        _require_test()
        try:
            payload = json.loads(request.form.get("payload", "{}"))
            item, created = execute_sandbox(
                request.form.get("connector", ""), request.form.get("operation", ""), payload,
                request.form.get("idempotency_key", ""), current_user,
            )
            result = {"transaction": _transaction_json(item), "reused": not created}
        except (json.JSONDecodeError, IntegrationRequestError, IdempotencyConflict) as error:
            result = {"error": str(error)}
        except Exception:
            current_app.logger.exception("Integration sandbox operation failed")
            db.session.rollback()
            result = {"error": "The sandbox operation could not be recorded."}
    connections = IntegrationConnection.query.order_by(IntegrationConnection.id).all()
    transactions = IntegrationTransaction.query.order_by(IntegrationTransaction.created_at.desc()).limit(50).all()
    return render_template("integration_hub.html", connections=connections, transactions=transactions, connectors=CONNECTORS, result=result)


@integration_bp.get("/api/integrations")
@login_required
def api_connections():
    _require_view()
    return jsonify([{"key": item.key, "name": item.name, "mode": item.mode, "status": item.status, "adapter_version": item.adapter_version, "source_of_truth": item.source_of_truth} for item in IntegrationConnection.query.order_by(IntegrationConnection.id)])


@integration_bp.get("/api/integrations/health")
@login_required
def api_health():
    _require_view()
    items = []
    for connection in IntegrationConnection.query.order_by(IntegrationConnection.id):
        latest = IntegrationTransaction.query.filter_by(connection_id=connection.id).order_by(IntegrationTransaction.created_at.desc()).first()
        items.append({"key": connection.key, "name": connection.name, "mode": connection.mode, "status": connection.status, "last_transaction": latest.transaction_id if latest else None, "last_transaction_status": latest.status if latest else None})
    return jsonify(items)


@integration_bp.get("/api/integrations/transactions")
@login_required
def api_transactions():
    _require_view()
    items = IntegrationTransaction.query.order_by(IntegrationTransaction.created_at.desc()).limit(100).all()
    return jsonify([_transaction_json(item) for item in items])


@integration_bp.get("/api/integrations/transactions/<int:transaction_pk>")
@login_required
def api_transaction_detail(transaction_pk):
    _require_view()
    item = db.get_or_404(IntegrationTransaction, transaction_pk)
    return jsonify(_transaction_json(item))


@integration_bp.post("/api/integrations/<connector>/test")
@login_required
def api_test(connector):
    _require_test()
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return jsonify({"error": "Request body must be a JSON object."}), 400
    try:
        item, created = execute_sandbox(connector, payload.pop("operation", ""), payload, request.headers.get("Idempotency-Key", ""), current_user)
    except IntegrationRequestError as error:
        return jsonify({"error": str(error)}), 400
    except IdempotencyConflict as error:
        return jsonify({"error": str(error)}), 409
    return jsonify({"created": created, "transaction": _transaction_json(item)}), 201 if created else 200


@integration_bp.get("/api/integrations/audit")
@login_required
def api_audit():
    _require_view()
    if not any(permission.name == "integration.audit" for permission in current_user.role_obj.permissions):
        abort(403)
    items = AuditLog.query.filter_by(module="Integration Hub").order_by(AuditLog.created_at.desc()).limit(100).all()
    return jsonify([{"action": item.action, "entity": item.entity, "details": item.details, "user_id": item.user_id, "created_at": item.created_at.isoformat()} for item in items])