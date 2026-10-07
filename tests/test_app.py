from smartchain import create_app
from smartchain.config import Config
from smartchain.models import ApprovalRecord, Driver, EvaluatorScore, ProcurementIntakeRequest, Tender, TransportAllocation, TransportPortalRequest, Vehicle
from smartchain.utils import safe_int


def test_integration_sandbox_transactions_are_idempotent_and_audited():
    from smartchain.models import AuditLog, IntegrationTransaction

    app = create_app({"TESTING": True, "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:", "ENV": "development"})
    client = app.test_client()
    client.get("/auth/dev-access")
    hub = client.get("/integrations")
    assert hub.status_code == 200
    assert b"SANDBOX ONLY" in hub.data

    payload = {"operation": "validate_supplier", "case_id": "SC-2026-000001", "csd_supplier_number": "CSD-TEST-001"}
    headers = {"Idempotency-Key": "SC-2026-000001:CSD:VALIDATE:1"}
    first = client.post("/api/integrations/csd/test", json=payload, headers=headers)
    replay = client.post("/api/integrations/csd/test", json=payload, headers=headers)
    assert first.status_code == 201
    assert replay.status_code == 200
    assert replay.json["created"] is False
    assert first.json["transaction"]["transaction_id"] == replay.json["transaction"]["transaction_id"]
    assert first.json["transaction"]["response"]["authoritative"] is False
    assert first.json["transaction"]["response"]["status"] == "SANDBOX_NOT_VERIFIED"

    conflict = client.post("/api/integrations/csd/test", json={**payload, "csd_supplier_number": "DIFFERENT"}, headers=headers)
    assert conflict.status_code == 409
    with app.app_context():
        assert IntegrationTransaction.query.count() == 1
        assert AuditLog.query.filter_by(module="Integration Hub").count() == 1


def test_integration_hub_denies_users_without_integration_permission():
    app = create_app({"TESTING": True, "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:", "ENV": "development"})
    client = app.test_client()
    client.post("/auth/login", data={"username": "employee"})
    assert client.get("/integrations").status_code == 403
    assert client.get("/api/integrations/health").status_code == 403
    assert client.post(
        "/api/integrations/csd/test",
        json={"operation": "validate_supplier", "csd_supplier_number": "CSD-TEST-001"},
        headers={"Idempotency-Key": "employee-attempt"},
    ).status_code == 403


def test_all_integration_sandbox_operations_return_non_authoritative_responses():
    app = create_app({"TESTING": True, "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:", "ENV": "development"})
    client = app.test_client()
    client.get("/auth/dev-access")
    operations = [
        ("twf", {"operation": "create_travel_request", "case_id": "SC-2026-000011", "request_id": "RQ-11", "destination": "Cape Town", "travel_date": "2026-11-15"}),
        ("twf", {"operation": "get_travel_request_status", "provider_reference": "SBX-REFERENCE"}),
        ("csd", {"operation": "validate_supplier", "csd_supplier_number": "CSD-TEST-002"}),
        ("etender", {"operation": "publish_tender", "case_id": "SC-2026-000012", "tender_number": "TND-12", "title": "Sandbox tender", "closing_date": "2026-12-01"}),
        ("finance", {"operation": "check_budget", "case_id": "SC-2026-000013", "cost_centre": "CC-13", "amount": 1200.50}),
        ("smartgov", {"operation": "submit_record_metadata", "case_id": "SC-2026-000014", "record_reference": "DOC-14", "document_hash": "a" * 64}),
    ]
    for index, (connector, payload) in enumerate(operations):
        response = client.post(
            f"/api/integrations/{connector}/test",
            json=payload,
            headers={"Idempotency-Key": f"operation-test-{index}"},
        )
        assert response.status_code == 201
        assert response.json["transaction"]["response"]["authoritative"] is False

    extra_field = client.post(
        "/api/integrations/csd/test",
        json={"operation": "validate_supplier", "csd_supplier_number": "CSD-TEST-003", "tax_pin": "must-not-be-sent"},
        headers={"Idempotency-Key": "reject-extra-field"},
    )
    assert extra_field.status_code == 400
    invalid_date = client.post(
        "/api/integrations/twf/test",
        json={"operation": "create_travel_request", "case_id": "SC-2026-000015", "request_id": "RQ-15", "destination": "Cape Town", "travel_date": "tomorrow"},
        headers={"Idempotency-Key": "reject-invalid-date"},
    )
    assert invalid_date.status_code == 400


def test_default_database_uri_is_sqlite():
    assert Config.SQLALCHEMY_DATABASE_URI.startswith("sqlite://")


def test_development_seed_contains_operational_tender_workspace(tmp_path):
    app = create_app({"SQLALCHEMY_DATABASE_URI": f"sqlite:///{(tmp_path / 'demo.db').as_posix()}", "ENV": "development"})
    with app.app_context():
        tender = Tender.query.filter_by(tender_number="TECH-2026-001").one()
        assert tender.title == "Technology Services Tender 2026"
        assert len(tender.bidders) == 20
        assert len(tender.criteria) == 5
        assert sum(len(criterion.subcriteria) for criterion in tender.criteria) == 4
        assert len(tender.screening_requirements) == 3
        assert len(tender.evaluator_assignments) == 5


def test_safe_int_handles_empty_missing_invalid_and_valid_values():
    assert safe_int(None) is None
    assert safe_int("") is None
    assert safe_int(" 42 ") == 42
    assert safe_int("invalid") is None
    assert safe_int("invalid", 7) == 7
    assert safe_int(3.0) == 3
    assert safe_int(3.5) is None
    assert safe_int(True) is None


def test_employee_creation_rejects_missing_integer_relationship_ids_cleanly():
    app = create_app({"TESTING": True, "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:", "ENV": "development"})
    client = app.test_client()
    client.get("/auth/dev-access")
    response = client.post("/org/employees/new", data={"employee_number": "DSD100", "first_name": "Missing", "last_name": "Ids"})
    assert response.status_code == 400
    assert b"Department, directorate, unit, and role are required." in response.data


def test_app_starts_and_serves_landing_page():
    app = create_app({"TESTING": True, "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:", "ENV": "development"})
    client = app.test_client()
    response = client.get("/")
    assert response.status_code == 200
    assert b"SmartChain" in response.data
    assert b"Sign In" in response.data
    assert b"Register" in response.data
    assert b"Directorate Transport Portal" in response.data
    assert b"Directorate RQ / Procurement Portal" in response.data


def test_operations_navigation_prioritises_tender_transport_and_rq():
    app = create_app({"TESTING": True, "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:", "ENV": "development"})
    client = app.test_client()
    client.get("/auth/dev-access")
    response = client.get("/dashboard")
    assert response.status_code == 200
    page = response.data
    assert page.index(b">Tender</span>") < page.index(b">Transport</span>") < page.index(b">RQ Command Centre</span>")


def test_employee_registration_creates_basic_role_account():
    app = create_app({"TESTING": True, "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:", "ENV": "development"})
    client = app.test_client()
    response = client.post("/auth/register", data={"first_name": "New", "surname": "Employee", "email": "new.employee@example.test", "employee_number": "DSD777", "department_id": "1", "directorate_id": "1", "unit_id": "1", "job_title": "Officer", "contact_number": "0830000000", "password": "SecurePass123!", "confirm_password": "SecurePass123!"}, follow_redirects=True)
    assert response.status_code == 200
    assert b"Registration successful" in response.data
    login_response = client.post("/auth/login", data={"username": "new.employee@example.test", "password": "SecurePass123!"}, follow_redirects=True)
    assert login_response.status_code == 200
    assert b"New Employee" in login_response.data


def test_development_test_admin_uses_passwordless_sign_in():
    app = create_app({"TESTING": True, "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:", "ENV": "development"})
    client = app.test_client()
    response = client.post("/auth/login", data={"username": "smartchain.admin"}, follow_redirects=True)
    assert response.status_code == 200
    assert b"Dashboard" in response.data


def test_employee_transport_portal_submits_into_workflow():
    app = create_app({"TESTING": True, "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:", "ENV": "development"})
    client = app.test_client()
    client.post("/auth/login", data={"username": "devadmin"})
    form = client.get("/transport-request/")
    assert form.status_code == 200
    response = client.post("/transport-request/", data={"purpose": "Regional monitoring visit", "travel_date": "2027-02-10", "departure_time": "07:30", "return_time": "17:00", "pickup_location": "Head Office", "destination": "Soweto", "passenger_count": "3"}, follow_redirects=True)
    assert response.status_code == 200
    assert b"Transport request submitted successfully" in response.data
    with app.app_context():
        request_record = TransportPortalRequest.query.one()
        assert request_record.status == "Submitted"
        assert request_record.destination == "Soweto"


def test_employee_cannot_submit_directorate_transport_case():
    app = create_app({"TESTING": True, "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:", "ENV": "development"})
    client = app.test_client()
    client.post("/auth/login", data={"username": "employee"})
    assert client.get("/transport-request/").status_code == 403
    assert client.get("/transport/").status_code == 403


def test_smartfleet_command_centre_and_case_timeline():
    from smartchain.models import TransportCaseEvent

    app = create_app({"TESTING": True, "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:", "ENV": "development"})
    client = app.test_client()
    client.post("/auth/login", data={"username": "devadmin"})
    response = client.post("/transport-request/", data={"purpose": "Directorate inspection", "travel_date": "2027-04-01", "pickup_location": "Head Office", "destination": "Pretoria", "passenger_count": "2"})
    assert response.status_code == 302
    with app.app_context():
        request_record = TransportPortalRequest.query.one()
        request_id = request_record.id
        assert TransportCaseEvent.query.filter_by(transport_request_id=request_id).count() == 2
    command = client.get("/transport/")
    assert command.status_code == 200
    assert b"Central Transport Intake Queue" in command.data
    case = client.get(f"/transport/requests/{request_id}")
    assert case.status_code == 200
    assert b"Digital footprint" in case.data
    status = client.post(f"/transport/requests/{request_id}/status", data={"status": "Validation", "comment": "Completeness check started"})
    assert status.status_code == 302
    with app.app_context():
        assert TransportPortalRequest.query.get(request_id).status == "Validation"
        assert TransportCaseEvent.query.filter_by(transport_request_id=request_id).count() == 3


def test_transport_maintenance_blocks_vehicle_allocation():
    from smartchain.extensions import db
    from smartchain.models import TransportMaintenance

    app = create_app({"TESTING": True, "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:", "ENV": "development"})
    client = app.test_client()
    client.post("/auth/login", data={"username": "devadmin"})
    client.post("/transport-request/", data={"purpose": "Maintenance test", "travel_date": "2027-05-01", "pickup_location": "Head Office", "destination": "Pretoria", "passenger_count": "1"})
    with app.app_context():
        request_id = TransportPortalRequest.query.one().id
        vehicle = Vehicle(registration_number="MAINT-001", fleet_number="FLT-MAINT", availability_status="AVAILABLE")
        db.session.add(vehicle)
        db.session.flush()
        db.session.add(TransportMaintenance(vehicle_id=vehicle.id, maintenance_type="Repair", status="OPEN"))
        db.session.commit()
        vehicle_id = vehicle.id
    blocked = client.post(f"/transport/requests/{request_id}/allocate", data={"vehicle_id": str(vehicle_id)}, follow_redirects=True)
    assert blocked.status_code == 409


def test_smartfleet_trip_authorisation_issue_start_and_return():
    from smartchain.extensions import db
    from smartchain.models import TransportTripAuthorisation, TransportVehicleIssue

    app = create_app({"TESTING": True, "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:", "ENV": "development"})
    client = app.test_client()
    client.post("/auth/login", data={"username": "devadmin"})
    client.post("/transport-request/", data={"purpose": "Execution test", "travel_date": "2027-06-01", "pickup_location": "Head Office", "destination": "Pretoria", "passenger_count": "1"})
    with app.app_context():
        request_record = TransportPortalRequest.query.one()
        vehicle = Vehicle(registration_number="EXEC-001", fleet_number="FLT-EXEC", current_odometer=1000, availability_status="AVAILABLE")
        driver = Driver(employee_name="Execution Driver", employee_number="DRV-EXEC", status="AUTHORISED")
        db.session.add_all([vehicle, driver])
        db.session.commit()
        request_id = request_record.id
        vehicle_id = vehicle.id
        driver_id = driver.id
    allocated = client.post(f"/transport/requests/{request_id}/allocate", data={"vehicle_id": str(vehicle_id), "driver_id": str(driver_id)})
    assert allocated.status_code == 302
    authorised = client.post(f"/transport/requests/{request_id}/authorise")
    assert authorised.status_code == 302
    with app.app_context():
        allocation = TransportAllocation.query.one()
        allocation_id = allocation.id
    issued = client.post(f"/transport/allocations/{allocation_id}/issue", data={"odometer": "1000", "fuel_level": "80", "condition": "Good", "acknowledgement": "Accepted"})
    assert issued.status_code == 302
    started = client.post(f"/transport/allocations/{allocation_id}/start")
    assert started.status_code == 302
    impossible_return = client.post(f"/transport/allocations/{allocation_id}/complete", data={"odometer_end": "999"})
    assert impossible_return.status_code == 400
    completed = client.post(f"/transport/allocations/{allocation_id}/complete", data={"odometer_end": "1125", "fuel_issued": "20", "fuel_cost": "450", "condition_notes": "Good"})
    assert completed.status_code == 302
    with app.app_context():
        assert TransportTripAuthorisation.query.one().status == "AUTHORISED"
        assert TransportVehicleIssue.query.one().odometer == 1000
        assert TransportAllocation.query.one().status == "COMPLETED"
        assert TransportPortalRequest.query.one().status == "Completed"


def test_employee_procurement_portal_reaches_scm_intake_with_documents_and_history():
    from io import BytesIO

    app = create_app({"TESTING": True, "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:", "ENV": "development"})
    client = app.test_client()
    client.post("/auth/login", data={"username": "devadmin"})
    response = client.post("/procurement-request/", data={"description": "Laptops for regional officers", "procurement_type": "Goods", "procurement_category": "ICT", "quantity": "5", "estimated_value": "85000", "business_need": "Enable service delivery", "justification": "Current devices are obsolete", "required_by_date": "2027-04-30", "delivery_location": "Head Office"}, follow_redirects=True)
    assert response.status_code == 200
    assert b"submitted successfully" in response.data
    with app.app_context():
        intake_request = ProcurementIntakeRequest.query.one()
        request_id = intake_request.id
        request_number = intake_request.request_number

    upload = client.post(f"/procurement-request/{request_id}/documents", data={"category": "Signed RQ", "title": "Signed requisition", "document": (BytesIO(b"signed-rq"), "signed-rq.pdf")}, content_type="multipart/form-data", follow_redirects=True)
    assert upload.status_code == 200
    assert b"Supporting document" in upload.data

    client.get("/auth/logout")
    client.get("/auth/dev-access")
    queue = client.get("/procurement-intake/")
    assert queue.status_code == 200
    assert request_number.encode() in queue.data
    for status in ["Received by SCM", "Preliminary Review", "Ready for Allocation", "Allocated"]:
        update = client.post(f"/procurement-intake/{request_id}", data={"status": status, "scm_notes": "Assigned for sourcing review"}, follow_redirects=True)
        assert update.status_code == 200
    assert update.status_code == 200
    assert b"Assigned for sourcing review" in update.data
    with app.app_context():
        updated = ProcurementIntakeRequest.query.get(request_id)
        assert updated.status == "Allocated"
        assert len(updated.documents) == 1
        assert len(updated.history) >= 2


def test_employee_cannot_submit_rq_and_authorised_directorate_can():
    app = create_app({"TESTING": True, "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:", "ENV": "development"})
    client = app.test_client()
    client.post("/auth/login", data={"username": "employee"})
    assert client.get("/procurement-request/").status_code == 403
    client.post("/auth/login", data={"username": "devadmin"})
    assert client.get("/procurement-request/").status_code == 200


def test_rq_command_centre_and_full_case_closure():
    from smartchain.models import ProcurementCaseEvent, ProcurementChecklistItem, ProcurementDelivery, ProcurementOrder

    app = create_app({"TESTING": True, "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:", "ENV": "development"})
    client = app.test_client()
    client.post("/auth/login", data={"username": "devadmin"})
    created = client.post("/procurement-request/", data={"employee_name": "Business Requester", "employee_number": "BR-100", "directorate": "Corporate Services", "description": "Network equipment", "specification": "Managed switches", "procurement_type": "Goods", "procurement_category": "ICT", "quantity": "5", "estimated_value": "100000", "business_need": "Service continuity", "justification": "Replace obsolete equipment", "required_by_date": "2027-08-01", "delivery_location": "Head Office"})
    assert created.status_code == 302
    with app.app_context():
        request_record = ProcurementIntakeRequest.query.one()
        request_id = request_record.id
        checklist_ids = [item.id for item in request_record.checklist_items]
        assert len(checklist_ids) == 4
        assert ProcurementCaseEvent.query.filter_by(request_id=request_id).count() == 1
    assert client.get("/procurement-intake/").status_code == 200
    for item_id in checklist_ids:
        assert client.post(f"/procurement-intake/{request_id}/checklist", data={"item_id": str(item_id), "status": "COMPLETE", "evidence_reference": "case-file"}).status_code == 302
    for status in ["Received by SCM", "Preliminary Review", "Ready for Allocation", "Allocated", "Sourcing in Progress", "Comparative Analysis", "Internal Control Review", "Approval"]:
        assert client.post(f"/procurement-intake/{request_id}", data={"status": status, "scm_notes": "Workflow review"}).status_code == 302
    approval = client.post(f"/procurement-intake/{request_id}/approval", data={"status": "APPROVED", "decision": "Approved after review"})
    assert approval.status_code == 302
    order = client.post(f"/procurement-intake/{request_id}/order", data={"order_reference": "PO-2027-001", "supplier_name": "Demo Supplier", "amount": "100000"})
    assert order.status_code == 302
    delivery = client.post(f"/procurement-intake/{request_id}/delivery", data={"status": "ACCEPTED", "quantity": "5", "comments": "Verified and accepted"})
    assert delivery.status_code == 302
    closed = client.post(f"/procurement-intake/{request_id}/close")
    assert closed.status_code == 302
    with app.app_context():
        assert ProcurementIntakeRequest.query.one().status == "Closed"
        assert ProcurementOrder.query.one().order_reference == "PO-2027-001"
        assert ProcurementDelivery.query.one().status == "ACCEPTED"
        assert ProcurementCaseEvent.query.filter_by(request_id=request_id).count() >= 12


def test_development_access_creates_session():
    app = create_app({"TESTING": True, "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:", "ENV": "development"})
    client = app.test_client()
    login_page = client.get("/auth/login")
    assert b"Development administrator shortcut" in login_page.data
    assert b'name="password"' not in login_page.data
    response = client.get("/auth/dev-access", follow_redirects=True)
    assert response.status_code == 200
    assert b"Dashboard" in response.data


def test_employee_cannot_access_tender_evaluation_workspace():
    app = create_app({"TESTING": True, "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:", "ENV": "development"})
    client = app.test_client()
    client.get("/auth/dev-access")
    client.post("/tenders/new", data={"tender_number": "TND-VIEW", "title": "Read-only Tender", "status": "Open"})
    with app.app_context():
        tender_id = Tender.query.filter_by(tender_number="TND-VIEW").one().id
    client.get("/auth/logout")
    client.post("/auth/login", data={"username": "employee"})

    listing = client.get("/tenders/")
    workspace = client.get(f"/tenders/{tender_id}")
    assert listing.status_code == 403
    assert workspace.status_code == 403
    assert client.get("/tenders/new").status_code == 403


def test_tender_index_launches_full_workspace():
    app = create_app({"TESTING": True, "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:", "ENV": "development"})
    client = app.test_client()
    client.get("/auth/dev-access")
    client.post("/tenders/new", data={"tender_number": "TND-LAUNCH", "title": "Workspace launch tender", "status": "Open"})
    with app.app_context():
        tender_id = Tender.query.filter_by(tender_number="TND-LAUNCH").one().id
    response = client.get("/tenders/")
    assert response.status_code == 200
    assert b"Tender Command Centre" in response.data
    assert b"Open Tender Workspace" in response.data
    assert f"/tenders/{tender_id}".encode() in response.data
    assert b"Criteria" in response.data
    assert b">BEC<" in response.data
    assert b">BAC<" in response.data


def test_standard_login_can_switch_from_employee_to_tender_administrator():
    app = create_app({"TESTING": True, "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:", "ENV": "development"})
    client = app.test_client()
    client.post("/auth/login", data={"username": "employee"})
    assert client.get("/tenders/").status_code == 403
    client.post("/auth/login", data={"username": "devadmin"})
    assert client.get("/tenders/").status_code == 200


def test_normal_user_login_uses_database_credentials():
    app = create_app({"TESTING": True, "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:", "ENV": "development"})
    client = app.test_client()
    response = client.post("/auth/login", data={"username": "manager", "password": "Password123!"}, follow_redirects=True)
    assert response.status_code == 200
    assert b"Procurement Manager" in response.data


def test_vehicle_csv_import_adds_multiple_vehicles():
    from io import BytesIO

    app = create_app({"TESTING": True, "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:", "ENV": "development"})
    client = app.test_client()
    client.get("/auth/dev-access")
    template = client.get("/transport/vehicles/import-template")
    assert template.status_code == 200
    assert b"registration_number,fleet_number" in template.data

    response = client.post(
        "/transport/vehicles/import",
        data={"vehicle_csv": (BytesIO(b"registration_number,fleet_number,make,model,fuel_type,current_odometer\nABC123,FLT-101,Toyota,Hilux,Diesel,25000\nXYZ789,FLT-102,Ford,Ranger,Diesel,18000\n"), "fleet.csv")},
        content_type="multipart/form-data",
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert b"Imported 2 vehicles successfully" in response.data
    with app.app_context():
        assert Vehicle.query.count() == 2
        assert Vehicle.query.filter_by(fleet_number="FLT-102").one().current_odometer == 18000


def test_vehicle_csv_import_rejects_invalid_file_without_partial_import():
    from io import BytesIO

    app = create_app({"TESTING": True, "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:", "ENV": "development"})
    client = app.test_client()
    client.get("/auth/dev-access")
    response = client.post(
        "/transport/vehicles/import",
        data={"vehicle_csv": (BytesIO(b"registration_number,fleet_number,current_odometer\nABC123,FLT-101,100\nXYZ789,FLT-102,not-a-number\n"), "fleet.csv")},
        content_type="multipart/form-data",
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert b"Import canceled" in response.data
    with app.app_context():
        assert Vehicle.query.count() == 0


def test_dashboard_actions_preserve_filter_context_and_empty_states():
    app = create_app({"TESTING": True, "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:", "ENV": "development"})
    client = app.test_client()
    client.get("/auth/dev-access")
    for path, message in [
        ("/procurement/?status=Active", b"No active procurement activities"),
        ("/requisition/?status=Open", b"No open requisitions"),
        ("/contract/?status=Active", b"No active contracts"),
        ("/approvals/?status=Pending", b"You have no pending approvals."),
    ]:
        response = client.get(path)
        assert response.status_code == 200
        assert message in response.data


def test_core_module_pages_load_for_authenticated_users():
    app = create_app({"TESTING": True, "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:", "ENV": "development"})
    client = app.test_client()
    client.get("/auth/dev-access")
    for path in [
        "/dashboard",
        "/org/employees",
        "/demand/",
        "/app/",
        "/requisition/",
        "/procurement/",
        "/supplier/",
        "/tenders/",
        "/bec/",
        "/bac/",
        "/contract/",
        "/transport/",
        "/travel/",
        "/asset/",
        "/controls/",
        "/risk/",
        "/audit/",
        "/reports/",
        "/security/",
        "/documents/",
        "/notifications/",
        "/search/?q=employee",
        "/admin/",
    ]:
        response = client.get(path)
        assert response.status_code == 200, path


def test_employee_creation_and_organisation_structure():
    app = create_app({"TESTING": True, "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:", "ENV": "development"})
    client = app.test_client()
    client.get("/auth/dev-access")

    dept_response = client.get("/org/departments")
    assert dept_response.status_code == 200

    employee_form = client.get("/org/employees/new")
    assert employee_form.status_code == 200

    create_response = client.post(
        "/org/employees/new",
        data={
            "employee_number": "DSD099",
            "first_name": "Test",
            "last_name": "Officer",
            "title": "Officer",
            "position": "Procurement Analyst",
            "email": "test@example.test",
            "phone": "123456",
            "department_id": "1",
            "directorate_id": "1",
            "unit_id": "1",
            "role_id": "1",
            "account_status": "active",
        },
        follow_redirects=True,
    )
    assert create_response.status_code == 200
    assert b"Employee created successfully" in create_response.data


def test_employee_360_detail_and_organisation_structure_pages():
    app = create_app({"TESTING": True, "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:", "ENV": "development"})
    client = app.test_client()
    client.get("/auth/dev-access")

    structure_response = client.get("/org/structure")
    assert structure_response.status_code == 200

    detail_response = client.get("/org/employees/1")
    assert detail_response.status_code == 200
    assert b"Employee 360" in detail_response.data


def test_demand_and_procurement_workflows_create_records():
    app = create_app({"TESTING": True, "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:", "ENV": "development"})
    client = app.test_client()
    client.get("/auth/dev-access")

    demand_form = client.get("/demand/new")
    assert demand_form.status_code == 200
    demand_response = client.post(
        "/demand/new",
        data={
            "title": "Fleet enhancement",
            "description": "Improve transport operations.",
            "responsible_unit": "Transport Unit",
            "estimated_cost": "180000",
            "priority": "High",
            "timing": "Q3",
            "justification": "Service continuity",
        },
        follow_redirects=True,
    )
    assert demand_response.status_code == 200
    assert b"Demand request created successfully" in demand_response.data

    app_form = client.get("/app/new")
    assert app_form.status_code == 200
    app_response = client.post(
        "/app/new",
        data={
            "item_name": "Vehicle Replacement",
            "estimated_value": "450000",
            "procurement_method": "Open Tender",
            "responsible_unit": "Transport Unit",
            "planned_date": "2026-11-01",
            "budget_allocation": "500000",
            "status": "Planned",
        },
        follow_redirects=True,
    )
    assert app_response.status_code == 200
    assert b"APP item created successfully" in app_response.data

    requisition_form = client.get("/requisition/new")
    assert requisition_form.status_code == 200
    requisition_response = client.post(
        "/requisition/new",
        data={
            "requisition_number": "RQ-2001",
            "requester": "Test Employee",
            "department": "National Department of Social Development",
            "directorate": "Corporate Services",
            "unit": "Supply Chain Management Unit",
            "description": "Laptop order",
            "motivation": "Work requirement",
            "estimated_value": "25000",
            "budget": "Budget 2026",
            "priority": "Medium",
            "status": "Submitted",
        },
        follow_redirects=True,
    )
    assert requisition_response.status_code == 200
    assert b"Requisition created successfully" in requisition_response.data

    procurement_form = client.get("/procurement/new")
    assert procurement_form.status_code == 200
    procurement_response = client.post(
        "/procurement/new",
        data={
            "title": "Laptop refresh",
            "procurement_method": "RFQ",
            "estimated_value": "25000",
            "status": "Draft",
            "recommendation": "Proceed",
        },
        follow_redirects=True,
    )
    assert procurement_response.status_code == 200
    assert b"Procurement request created successfully" in procurement_response.data

    supplier_form = client.get("/supplier/new")
    assert supplier_form.status_code == 200
    supplier_response = client.post(
        "/supplier/new",
        data={
            "name": "New Supplier Co",
            "registration_number": "REG-900",
            "service_categories": "ICT Services",
            "status": "Active",
            "contact_email": "sales@newsupplier.test",
            "phone": "5550000",
        },
        follow_redirects=True,
    )
    assert supplier_response.status_code == 200
    assert b"Supplier created successfully" in supplier_response.data

    tender_form = client.get("/tenders/new")
    assert tender_form.status_code == 200
    tender_response = client.post(
        "/tenders/new",
        data={
            "tender_number": "TND-2001",
            "title": "ICT Support Services",
            "description": "Support services contract",
            "estimated_value": "300000",
            "closing_date": "2026-12-31",
            "status": "Open",
        },
        follow_redirects=True,
    )
    assert tender_response.status_code == 200
    assert b"Tender created successfully" in tender_response.data


def test_governance_and_control_workflows_create_records():
    app = create_app({"TESTING": True, "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:", "ENV": "development"})
    client = app.test_client()
    client.get("/auth/dev-access")

    contract_form = client.get("/contract/new")
    assert contract_form.status_code == 200
    contract_response = client.post(
        "/contract/new",
        data={
            "contract_number": "CON-2001",
            "supplier": "Test Supply Co",
            "tender": "TND-2001",
            "start_date": "2026-10-01",
            "end_date": "2027-09-30",
            "value": "320000",
            "status": "Active",
        },
        follow_redirects=True,
    )
    assert contract_response.status_code == 200
    assert b"Contract created successfully" in contract_response.data

    transport_form = client.get("/transport/new")
    assert transport_form.status_code == 200
    transport_response = client.post(
        "/transport/new",
        data={
            "title": "Site visit",
            "origin": "Pretoria",
            "destination": "Bloemfontein",
            "purpose": "Monitoring outreach",
            "status": "Approved",
        },
        follow_redirects=True,
    )
    assert transport_response.status_code == 200
    assert b"Trip request created successfully" in transport_response.data

    travel_form = client.get("/travel/new")
    assert travel_form.status_code == 200
    travel_response = client.post(
        "/travel/new",
        data={
            "title": "Stakeholder engagement",
            "purpose": "Training and oversight",
            "destination": "Johannesburg",
            "status": "Approved",
        },
        follow_redirects=True,
    )
    assert travel_response.status_code == 200
    assert b"Travel request created successfully" in travel_response.data

    asset_form = client.get("/asset/new")
    assert asset_form.status_code == 200
    asset_response = client.post(
        "/asset/new",
        data={
            "asset_number": "AST-2001",
            "description": "Laptop fleet",
            "category": "IT Equipment",
            "location": "Head Office",
            "value": "22000",
            "condition": "Good",
            "status": "Active",
        },
        follow_redirects=True,
    )
    assert asset_response.status_code == 200
    assert b"Asset created successfully" in asset_response.data

    control_form = client.get("/controls/new")
    assert control_form.status_code == 200
    control_response = client.post(
        "/controls/new",
        data={
            "control_objective": "Prevent duplicate payments",
            "process_name": "Procurement approval",
            "risk_rating": "High",
            "status": "Active",
        },
        follow_redirects=True,
    )
    assert control_response.status_code == 200
    assert b"Internal control created successfully" in control_response.data

    risk_form = client.get("/risk/new")
    assert risk_form.status_code == 200
    risk_response = client.post(
        "/risk/new",
        data={
            "title": "Supplier concentration risk",
            "category": "Market",
            "likelihood": "Medium",
            "impact": "High",
            "risk_rating": "High",
            "status": "Open",
        },
        follow_redirects=True,
    )
    assert risk_response.status_code == 200
    assert b"Risk item created successfully" in risk_response.data


def test_evaluation_and_document_workflows_create_records():
    app = create_app({"TESTING": True, "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:", "ENV": "development"})
    client = app.test_client()
    client.get("/auth/dev-access")

    tender_response = client.post(
        "/tenders/new",
        data={
            "tender_number": "TND-3001",
            "title": "Digital Service Platform",
            "description": "Platform implementation tender",
            "estimated_value": "500000",
            "closing_date": "2027-01-31",
            "status": "Open",
        },
    )
    assert tender_response.status_code == 302

    bec_form = client.get("/bec/new")
    assert bec_form.status_code == 200
    bec_response = client.post(
        "/bec/new",
        data={
            "tender_id": "1",
            "title": "Evaluation Committee for ICT Tender",
            "evaluation_status": "In Progress",
        },
        follow_redirects=True,
    )
    assert bec_response.status_code == 200
    assert b"BEC record created successfully" in bec_response.data

    bac_form = client.get("/bac/new")
    assert bac_form.status_code == 200
    bac_response = client.post(
        "/bac/new",
        data={
            "tender_id": "1",
            "title": "Adjudication Committee",
            "decision": "Recommended for award",
            "status": "Pending",
        },
        follow_redirects=True,
    )
    assert bac_response.status_code == 200
    assert b"BAC record created successfully" in bac_response.data

    document_form = client.get("/documents/new")
    assert document_form.status_code == 200
    document_response = client.post(
        "/documents/new",
        data={
            "title": "Tender Evaluation Report",
            "document_type": "Report",
            "link_type": "tender",
            "link_id": "1",
            "uploaded_by": "System Administrator",
        },
        follow_redirects=True,
    )
    assert document_response.status_code == 200
    assert b"Document created successfully" in document_response.data

    notification_form = client.get("/notifications/new")
    assert notification_form.status_code == 200
    notification_response = client.post(
        "/notifications/new",
        data={
            "title": "Tender award update",
            "message": "A tender decision is ready for review.",
            "is_read": "false",
        },
        follow_redirects=True,
    )
    assert notification_response.status_code == 200
    assert b"Notification created successfully" in notification_response.data


def test_tender_workspace_bidder_criteria_and_evaluation_flow(tmp_path):
    from io import BytesIO
    from smartchain.models import TenderDocument

    app = create_app({"TESTING": True, "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:", "ENV": "development", "TENDER_DOCUMENT_FOLDER": str(tmp_path)})
    client = app.test_client()
    client.get("/auth/dev-access")
    client.post("/tenders/new", data={"tender_number": "TND-4001", "title": "Community Services", "estimated_value": "100000", "status": "Under Evaluation"})
    with app.app_context():
        tender_id = Tender.query.filter_by(tender_number="TND-4001").first().id

    workspace = client.get(f"/tenders/{tender_id}")
    assert workspace.status_code == 200
    assert b"Bid comparison" in workspace.data
    assert b"Register the participating bidders and their bid prices." in workspace.data

    bidder_response = client.post(f"/tenders/{tender_id}/bidders/new", data={"legal_name": "Amos Trading", "supplier_reference": "SUP-001", "bid_price": "95000", "compliance_status": "Pass"})
    assert bidder_response.status_code == 302
    with app.app_context():
        bidder_id = Tender.query.get(tender_id).bidders[0].id
    submission_response = client.post(
        f"/tenders/{tender_id}/bidders/{bidder_id}/submissions/new",
        data={"document_category": "Technical Document", "document_title": "Technical proposal", "document_file": (BytesIO(b"Technical response document"), "technical.pdf")},
        content_type="multipart/form-data",
    )
    assert submission_response.status_code == 302
    compliance_response = client.post(f"/tenders/{tender_id}/compliance/new", data={"requirement": "Signed declaration", "submitted": "true", "valid": "true", "evidence_reference": "repo/tnd-4001/amos/declaration.pdf"})
    assert compliance_response.status_code == 302
    criterion_response = client.post(f"/tenders/{tender_id}/criteria/new", data={"name": "Technical Capability", "weight": "100", "max_score": "5", "scoring_framework": "1-5"})
    assert criterion_response.status_code == 302

    with app.app_context():
        tender = Tender.query.get(tender_id)
        bidder_id = tender.bidders[0].id
        criterion_id = tender.criteria[0].id
    score_response = client.post(f"/tenders/{tender_id}/evaluations/new", data={"bidder_id": str(bidder_id), "criterion_id": str(criterion_id), "score": "4", "comments": "Strong technical response", "action": "submit"}, follow_redirects=True)
    assert score_response.status_code == 200
    assert b"Evaluated" in score_response.data
    assert b"80.00" in score_response.data
    assert b"Bid price" in score_response.data
    assert b"R 95000.00" in score_response.data
    assert b"Signed declaration" in score_response.data
    assert b"Technical Document" in score_response.data
    with app.app_context():
        uploaded_document_id = TenderDocument.query.filter(TenderDocument.category.like("Bidder%Technical Document")).one().id
    downloaded = client.get(f"/tenders/{tender_id}/documents/{uploaded_document_id}/download")
    assert downloaded.data == b"Technical response document"


def test_submitted_evaluation_is_locked_until_authorised_reopen():
    app = create_app({"TESTING": True, "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:", "ENV": "development"})
    client = app.test_client()
    client.get("/auth/dev-access")
    client.post("/tenders/new", data={"tender_number": "TND-LOCK", "title": "Locked evaluation", "status": "Under Evaluation"})
    with app.app_context():
        tender = Tender.query.filter_by(tender_number="TND-LOCK").first()
        tender_id = tender.id
    client.post(f"/tenders/{tender_id}/bidders/new", data={"legal_name": "Locked Bidder", "bid_price": "100"})
    client.post(f"/tenders/{tender_id}/criteria/new", data={"name": "Technical", "weight": "100", "max_score": "5"})
    with app.app_context():
        tender = Tender.query.get(tender_id)
        bidder_id = tender.bidders[0].id
        criterion_id = tender.criteria[0].id
    submitted = client.post(f"/tenders/{tender_id}/evaluations/new", data={"bidder_id": bidder_id, "criterion_id": criterion_id, "score": "4", "action": "submit"})
    assert submitted.status_code == 302
    locked = client.post(f"/tenders/{tender_id}/evaluations/new", data={"bidder_id": bidder_id, "criterion_id": criterion_id, "score": "2", "action": "submit"})
    assert locked.status_code == 409
    with app.app_context():
        evaluation = EvaluatorScore.query.one()
        evaluation_id = evaluation.id
    reopened = client.post(f"/tenders/{tender_id}/evaluations/{evaluation_id}/reopen", data={"reason": "Correct a transcription error"})
    assert reopened.status_code == 302
    with app.app_context():
        assert EvaluatorScore.query.one().status == "Draft"


def test_tender_screening_assignment_and_subcriterion_scoring_are_enforced():
    from smartchain.extensions import db
    from smartchain.models import EvaluatorSubcriterionScore, TenderEvaluatorAssignment, TenderScreeningRequirement, TenderScreeningResult, TenderSubcriterion, User

    app = create_app({"TESTING": True, "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:", "ENV": "development"})
    client = app.test_client()
    client.get("/auth/dev-access")
    client.post("/tenders/new", data={"tender_number": "TND-SCREEN", "title": "Screened Tender", "status": "Under Evaluation"})
    with app.app_context():
        tender = Tender.query.filter_by(tender_number="TND-SCREEN").one()
        tender_id = tender.id
        evaluator_role = db.session.query(__import__("smartchain.models", fromlist=["Role"]).Role).filter_by(name="BEC Member").one()
        assigned_evaluator = User(username="assigned.evaluator", email="assigned.evaluator@example.test", full_name="Assigned Evaluator", role_id=evaluator_role.id, is_active=True)
        assigned_evaluator.set_password("EvaluatorPass123!")
        unassigned_evaluator = User(username="unassigned.evaluator", email="unassigned.evaluator@example.test", full_name="Unassigned Evaluator", role_id=evaluator_role.id, is_active=True)
        unassigned_evaluator.set_password("EvaluatorPass123!")
        db.session.add_all([assigned_evaluator, unassigned_evaluator])
        db.session.commit()
        assigned_id = assigned_evaluator.id
        unassigned_id = unassigned_evaluator.id

    client.post(f"/tenders/{tender_id}/bidders/new", data={"legal_name": "Screened Bidder", "bid_price": "5000"})
    client.post(f"/tenders/{tender_id}/criteria/new", data={"name": "Technical", "weight": "100", "max_score": "5", "scoring_framework": "Points", "mandatory": "true"})
    with app.app_context():
        tender = Tender.query.get(tender_id)
        bidder_id = tender.bidders[0].id
        criterion_id = tender.criteria[0].id
    client.post(f"/tenders/{tender_id}/criteria/{criterion_id}/subcriteria/new", data={"name": "Team", "max_points": "2"})
    client.post(f"/tenders/{tender_id}/criteria/{criterion_id}/subcriteria/new", data={"name": "Method", "max_points": "3"})
    client.post(f"/tenders/{tender_id}/screening", data={"action": "add_requirement", "name": "Signed declaration", "category": "Eligibility", "mandatory": "true"})
    with app.app_context():
        requirement_id = TenderScreeningRequirement.query.one().id
    client.post(f"/tenders/{tender_id}/evaluators", data={"user_id": assigned_id})

    client.get("/auth/logout")
    client.post("/auth/login", data={"username": "unassigned.evaluator", "password": "EvaluatorPass123!"})
    with app.app_context():
        assignment_count = TenderEvaluatorAssignment.query.count()
    assert assignment_count == 1
    assert client.get(f"/tenders/{tender_id}").status_code == 403
    assert client.get(f"/tenders/{tender_id}/committees/BEC/meetings").status_code == 403
    forbidden = client.get(f"/tenders/{tender_id}/evaluations/new")
    assert forbidden.status_code == 403

    client.get("/auth/logout")
    client.get("/auth/dev-access")
    client.post(f"/tenders/{tender_id}/screening", data={"action": "update_result", "requirement_id": requirement_id, "bidder_id": bidder_id, "result": "FAIL", "evidence_reference": "bid.pdf#page=2", "comments": "Declaration missing"})
    client.get("/auth/logout")
    client.post("/auth/login", data={"username": "assigned.evaluator", "password": "EvaluatorPass123!"})
    assert client.get(f"/tenders/{tender_id}/committees/BEC/meetings").status_code == 200
    assert client.get(f"/tenders/{tender_id}/committees/BAC/meetings").status_code == 403
    blocked = client.post(f"/tenders/{tender_id}/evaluations/new", data={"bidder_id": str(bidder_id), "criterion_id": str(criterion_id), "subcriterion_1": "2", "subcriterion_2": "3", "action": "submit"})
    assert blocked.status_code == 409

    client.get("/auth/logout")
    client.get("/auth/dev-access")
    client.post(f"/tenders/{tender_id}/screening", data={"action": "update_result", "requirement_id": requirement_id, "bidder_id": bidder_id, "result": "PASS", "evidence_reference": "declaration.pdf", "comments": "Verified"})
    client.get("/auth/logout")
    client.post("/auth/login", data={"username": "assigned.evaluator", "password": "EvaluatorPass123!"})
    submitted = client.post(f"/tenders/{tender_id}/evaluations/new", data={"bidder_id": str(bidder_id), "criterion_id": str(criterion_id), "subcriterion_1": "2", "subcriterion_2": "3", "action": "submit"})
    assert submitted.status_code == 302
    with app.app_context():
        score = EvaluatorScore.query.one()
        assert score.score == 5
        assert score.status == "Submitted"
        assert EvaluatorSubcriterionScore.query.count() == 2
        assert TenderScreeningResult.query.one().result == "PASS"


def test_bidder_import_requires_confirmation_and_tender_committee_meetings_are_scoped():
    from io import BytesIO
    from smartchain.models import TenderBidder, TenderCommitteeMeeting, TenderCommitteeMember

    app = create_app({"TESTING": True, "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:", "ENV": "development"})
    client = app.test_client()
    client.get("/auth/dev-access")
    client.post("/tenders/new", data={"tender_number": "TND-IMPORT", "title": "Import Workflow", "status": "Under Evaluation"})
    with app.app_context():
        tender_id = Tender.query.filter_by(tender_number="TND-IMPORT").one().id

    review = client.post(
        f"/tenders/{tender_id}/bidders/import",
        data={"bidder_file": (BytesIO(b"legal_name,supplier_reference,bid_price\nCompany A,REF-001,1000\nCompany B,REF-002,1200\n"), "bidders.csv")},
        content_type="multipart/form-data",
    )
    assert review.status_code == 200
    assert b"2 bidder records detected" in review.data
    with app.app_context():
        assert TenderBidder.query.count() == 0

    imported = client.post(
        f"/tenders/{tender_id}/bidders/import/confirm",
        data={"include_row": ["0", "1"], "legal_name": ["Company A", "Company B"], "supplier_reference": ["REF-001", "REF-002"], "bid_price": ["1000", "1200"]},
        follow_redirects=True,
    )
    assert imported.status_code == 200
    assert b"Imported 2 reviewed bidder records" in imported.data
    with app.app_context():
        assert TenderBidder.query.count() == 2

    meeting_page = client.get(f"/tenders/{tender_id}/committees/BEC/meetings")
    assert meeting_page.status_code == 200
    meeting_response = client.post(
        f"/tenders/{tender_id}/committees/BEC/meetings",
        data={"meeting_number": "BEC-01", "meeting_at": "2026-10-01T09:00", "venue": "Boardroom", "chair": "Chair", "secretariat": "Secretary", "status": "Planned", "member_name": ["Member One"], "member_role": ["Evaluator"], "member_organization": ["DSD"]},
    )
    assert meeting_response.status_code == 302
    with app.app_context():
        meeting = TenderCommitteeMeeting.query.one()
        meeting_id = meeting.id
        member_id = TenderCommitteeMember.query.one().id
    attendance = client.post(
        f"/tenders/{tender_id}/committees/meetings/{meeting_id}/attendance",
        data={"attended_member_ids": [str(member_id)]},
    )
    assert attendance.status_code == 302
    with app.app_context():
        assert TenderCommitteeMember.query.one().attended is True

    report = client.get(f"/tenders/{tender_id}/committees/BEC/report.pdf")
    assert report.status_code == 200
    assert report.mimetype == "application/pdf"
    assert report.data.startswith(b"%PDF")
    spreadsheet = client.get(f"/tenders/{tender_id}/committees/BEC/report.xlsx")
    assert spreadsheet.status_code == 200
    assert spreadsheet.mimetype == "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    from openpyxl import load_workbook
    workbook = load_workbook(BytesIO(spreadsheet.data), read_only=True, data_only=True)
    assert workbook["Tender overview"]["B2"].value == "TND-IMPORT"
    assert workbook["Bidders and evaluation"]["A2"].value == "Company A"
    assert workbook["BEC meetings"]["A2"].value == "BEC-01"

    with app.app_context():
        selected_bidder_id = TenderBidder.query.order_by(TenderBidder.id).first().id
    outcome = client.post(
        f"/tenders/{tender_id}/outcome",
        data={"status": "Approved", "decision_type": "Award recommendation approved", "bidder_id": str(selected_bidder_id), "rationale": "Authorised decision recorded for test workflow."},
    )
    assert outcome.status_code == 302
    handoff = client.post(
        f"/tenders/{tender_id}/contract",
        data={"contract_number": "CON-TND-IMPORT", "start_date": "2026-10-01", "end_date": "2027-09-30", "value": "1000", "status": "Draft"},
    )
    assert handoff.status_code == 302
    with app.app_context():
        from smartchain.models import Contract, TenderOutcome, TenderReportRecord
        assert TenderOutcome.query.one().status == "Approved"
        assert Contract.query.filter_by(contract_number="CON-TND-IMPORT", tender="TND-IMPORT").one().supplier == "Company A"
        assert [record.version for record in TenderReportRecord.query.order_by(TenderReportRecord.version).all()] == [1, 2]


def test_tender_document_uploads_preserve_and_download_versions(tmp_path):
    from io import BytesIO
    from smartchain.models import TenderDocument

    app = create_app({"TESTING": True, "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:", "ENV": "development", "TENDER_DOCUMENT_FOLDER": str(tmp_path)})
    client = app.test_client()
    client.get("/auth/dev-access")
    client.post("/tenders/new", data={"tender_number": "TND-DOCS", "title": "Versioned Documents", "status": "Open"})
    with app.app_context():
        tender_id = Tender.query.filter_by(tender_number="TND-DOCS").one().id

    for document_content in (b"version one", b"version two"):
        response = client.post(
            f"/tenders/{tender_id}/documents",
            data={"category": "Tender document", "description": "Approved tender pack", "document": (BytesIO(document_content), "tender.pdf")},
            content_type="multipart/form-data",
            follow_redirects=True,
        )
        assert response.status_code == 200

    with app.app_context():
        versions = TenderDocument.query.order_by(TenderDocument.version).all()
        assert [document.version for document in versions] == [1, 2]
        document_ids = [document.id for document in versions]
    first_version = client.get(f"/tenders/{tender_id}/documents/{document_ids[0]}/download")
    second_version = client.get(f"/tenders/{tender_id}/documents/{document_ids[1]}/download")
    assert first_version.data == b"version one"
    assert second_version.data == b"version two"


def test_tender_consolidation_handles_twenty_bidders_five_evaluators_and_five_criteria():
    from smartchain.extensions import db
    from smartchain.models import Role, TenderBidder, TenderCriterion, TenderCriterionConfig, TenderEvaluatorAssignment, User

    app = create_app({"TESTING": True, "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:", "ENV": "development"})
    client = app.test_client()
    client.get("/auth/dev-access")
    with app.app_context():
        role = Role.query.filter_by(name="BEC Member").one()
        admin = User.query.filter_by(username="devadmin").one()
        tender = Tender(tender_number="TND-20X5", title="Twenty bidder consolidation", status="Under Evaluation")
        db.session.add(tender)
        db.session.flush()
        evaluators = [
            User(username=f"tender-evaluator-{index}", email=f"tender-evaluator-{index}@example.test", full_name=f"Evaluator {index}", role_id=role.id, is_active=True)
            for index in range(1, 6)
        ]
        bidders = [TenderBidder(tender=tender, legal_name=f"Company {index:02d}", bid_price=100000 + index * 1000) for index in range(1, 21)]
        criteria = [
            TenderCriterion(tender=tender, name=f"Criterion {index}", weight=20, max_score=5, scoring_framework="1-5", config=TenderCriterionConfig(category="Functionality", position=index - 1))
            for index in range(1, 6)
        ]
        db.session.add_all(evaluators + bidders + criteria)
        db.session.flush()
        db.session.add_all([
            TenderEvaluatorAssignment(tender=tender, user=evaluator, assigned_by=admin)
            for evaluator in evaluators
        ])
        db.session.add_all([
            EvaluatorScore(tender=tender, bidder=bidder, criterion=criterion, evaluator=evaluator, score=4, status="Submitted")
            for bidder in bidders
            for criterion in criteria
            for evaluator in evaluators
        ])
        db.session.commit()
        tender_id = tender.id

    workspace = client.get(f"/tenders/{tender_id}")
    assert workspace.status_code == 200
    assert b"500 / 500 score sheets submitted" in workspace.data
    assert b"20" in workspace.data
    assert b"80.00" in workspace.data


def test_startup_migrates_missing_evaluator_lock_columns(tmp_path):
    import sqlite3

    from smartchain.extensions import db
    from sqlalchemy import inspect

    legacy_database = tmp_path / "legacy-tender.db"
    with sqlite3.connect(legacy_database) as connection:
        connection.execute("CREATE TABLE evaluator_score (id INTEGER PRIMARY KEY)")
    app = create_app({
        "TESTING": True,
        "SQLALCHEMY_DATABASE_URI": f"sqlite:///{legacy_database.as_posix()}",
        "ENV": "development",
    })
    with app.app_context():
        columns = {column["name"] for column in inspect(db.engine).get_columns("evaluator_score")}
    assert {"locked_at", "reopened_at", "reopen_reason"}.issubset(columns)


def test_full_tender_routes_complete_twenty_bidder_five_evaluator_lifecycle():
    from io import BytesIO

    from smartchain.extensions import db
    from smartchain.models import (
        Role,
        TenderBidder,
        TenderCommitteeMeeting,
        TenderCriterion,
        TenderEvaluatorAssignment,
        TenderScreeningRequirement,
        TenderStageEvent,
        TenderSubcriterion,
        User,
    )

    app = create_app({"TESTING": True, "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:", "ENV": "development"})
    client = app.test_client()
    client.get("/auth/dev-access")
    client.post(
        "/tenders/new",
        data={
            "tender_number": "TND-ROUTE-20X5",
            "title": "Technology Services Tender 2026",
            "description": "Full route-driven lifecycle scenario",
            "estimated_value": "2500000",
            "status": "Under Evaluation",
            "evaluation_methodology": "Functionality with equal criterion weights",
            "functionality_required": "true",
            "minimum_functionality_threshold": "60",
        },
    )
    with app.app_context():
        tender_id = Tender.query.filter_by(tender_number="TND-ROUTE-20X5").one().id

    bidder_csv = "legal_name,supplier_reference,bid_price,registration_number,contact_email\n" + "".join(
        f"Technology Company {index:02d},REF-{index:03d},{100000 + index * 1000},REG-{index:03d},contact{index}@example.test\n"
        for index in range(1, 21)
    )
    review = client.post(
        f"/tenders/{tender_id}/bidders/import",
        data={"bidder_file": (BytesIO(bidder_csv.encode()), "technology-bidders.csv")},
        content_type="multipart/form-data",
    )
    assert review.status_code == 200
    assert b"20 bidder records detected" in review.data
    staged_bidder_names = [f"Technology Company {index:02d}" for index in range(1, 21)]
    imported = client.post(
        f"/tenders/{tender_id}/bidders/import/confirm",
        data={
            "include_row": [str(index) for index in range(20)],
            "legal_name": staged_bidder_names,
            "supplier_reference": [f"REF-{index:03d}" for index in range(1, 21)],
            "bid_price": [str(100000 + index * 1000) for index in range(1, 21)],
            "registration_number": [f"REG-{index:03d}" for index in range(1, 21)],
            "contact_email": [f"contact{index}@example.test" for index in range(1, 21)],
        },
    )
    assert imported.status_code == 302

    criterion_ids = []
    for index in range(1, 6):
        criterion_response = client.post(
            f"/tenders/{tender_id}/criteria/new",
            data={
                "name": f"Functionality criterion {index}",
                "category": "Functionality",
                "weight": "20",
                "max_score": "5",
                "scoring_framework": "1-5",
                "minimum_qualifying_score": "3",
                "mandatory": "true" if index == 1 else "false",
            },
        )
        assert criterion_response.status_code == 302
    with app.app_context():
        criterion_ids = [criterion.id for criterion in TenderCriterion.query.order_by(TenderCriterion.id).all()]
        bidder_ids = [bidder.id for bidder in TenderBidder.query.order_by(TenderBidder.id).all()]
    subcriterion_response = client.post(
        f"/tenders/{tender_id}/criteria/{criterion_ids[0]}/subcriteria/new",
        data={"name": "Technical team", "max_points": "5", "description": "Named team capability"},
    )
    assert subcriterion_response.status_code == 302
    with app.app_context():
        subcriterion_id = TenderSubcriterion.query.one().id

    screening = client.post(
        f"/tenders/{tender_id}/screening",
        data={"action": "add_requirement", "name": "Signed declaration", "category": "Mandatory", "mandatory": "true"},
    )
    assert screening.status_code == 302
    with app.app_context():
        requirement_id = TenderScreeningRequirement.query.one().id
    for bidder_id in bidder_ids:
        result = client.post(
            f"/tenders/{tender_id}/screening",
            data={"action": "update_result", "requirement_id": requirement_id, "bidder_id": bidder_id, "result": "PASS", "evidence_reference": "declaration.pdf", "comments": "Verified"},
        )
        assert result.status_code == 302

    with app.app_context():
        evaluator_role = Role.query.filter_by(name="BEC Member").one()
        admin = User.query.filter_by(username="devadmin").one()
        evaluators = []
        for index in range(1, 6):
            evaluator = User(username=f"route-evaluator-{index}", email=f"route-evaluator-{index}@example.test", full_name=f"Route Evaluator {index}", role_id=evaluator_role.id, is_active=True)
            evaluator.set_password("EvaluatorPass123!")
            evaluators.append(evaluator)
        db.session.add_all(evaluators)
        db.session.commit()
        evaluator_ids = [evaluator.id for evaluator in evaluators]
        admin_id = admin.id

    for evaluator_id in evaluator_ids:
        assignment = client.post(f"/tenders/{tender_id}/evaluators", data={"user_id": evaluator_id})
        assert assignment.status_code == 302

    for evaluator_index in range(1, 6):
        client.get("/auth/logout")
        login = client.post(
            "/auth/login",
            data={"username": f"route-evaluator-{evaluator_index}", "password": "EvaluatorPass123!"},
        )
        assert login.status_code == 302
        for bidder_id in bidder_ids:
            for criterion_index, criterion_id in enumerate(criterion_ids):
                score_data = {
                    "bidder_id": str(bidder_id),
                    "criterion_id": str(criterion_id),
                    "action": "submit",
                    "comments": f"Evaluator {evaluator_index} reviewed the submission.",
                }
                if criterion_index == 0:
                    score_data[f"subcriterion_{subcriterion_id}"] = "4"
                else:
                    score_data["score"] = "4"
                score_response = client.post(f"/tenders/{tender_id}/evaluations/new", data=score_data)
                assert score_response.status_code == 302

    client.get("/auth/logout")
    client.get("/auth/dev-access")
    workspace = client.get(f"/tenders/{tender_id}")
    assert workspace.status_code == 200
    assert b"500 / 500 score sheets submitted" in workspace.data
    assert b"80.00" in workspace.data
    assert b"Current position" in workspace.data

    for committee_type in ("BEC", "BAC"):
        meeting_response = client.post(
            f"/tenders/{tender_id}/committees/{committee_type}/meetings",
            data={"meeting_number": f"{committee_type}-01", "meeting_at": "2026-10-10T09:00", "venue": "Committee room", "chair": "Chair", "secretariat": "Secretary", "status": "Completed", "member_name": ["Member"], "member_role": ["Chair"], "member_organization": ["DSD"], "minutes": "Review completed.", "resolution": "Proceed to next authorised stage."},
        )
        assert meeting_response.status_code == 302
        assert client.get(f"/tenders/{tender_id}/committees/{committee_type}/report.pdf").mimetype == "application/pdf"
        assert client.get(f"/tenders/{tender_id}/committees/{committee_type}/report.xlsx").status_code == 200

    with app.app_context():
        selected_bidder_id = bidder_ids[0]
    outcome = client.post(
        f"/tenders/{tender_id}/outcome",
        data={"status": "Approved", "decision_type": "Authorised award", "bidder_id": selected_bidder_id, "rationale": "Recorded by authorised test user after comparative review."},
    )
    assert outcome.status_code == 302
    contract = client.post(
        f"/tenders/{tender_id}/contract",
        data={"contract_number": "CON-ROUTE-20X5", "start_date": "2026-11-01", "end_date": "2027-10-31", "status": "Draft"},
    )
    assert contract.status_code == 302
    with app.app_context():
        assert EvaluatorScore.query.filter_by(tender_id=tender_id, status="Submitted").count() == 500
        assert TenderEvaluatorAssignment.query.filter_by(tender_id=tender_id, active=True).count() == 5
        assert TenderCommitteeMeeting.query.filter_by(tender_id=tender_id).count() == 2
        assert TenderStageEvent.query.filter_by(tender_id=tender_id).count() >= 500


def test_pending_approval_requires_authorised_decision():
    app = create_app({"TESTING": True, "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:", "ENV": "development"})
    client = app.test_client()
    client.get("/auth/dev-access")
    with app.app_context():
        approval = ApprovalRecord(title="Budget approval", entity_type="Budget", entity_id=1, approver="Development Administrator", status="Pending")
        from smartchain.extensions import db
        db.session.add(approval)
        db.session.commit()
        approval_id = approval.id
    decision = client.post(f"/approvals/{approval_id}/decision", data={"decision": "Approved", "comments": "Reviewed"})
    assert decision.status_code == 302
    with app.app_context():
        assert ApprovalRecord.query.get(approval_id).status == "Approved"


def test_transport_officer_allocates_and_closes_trip_with_mileage_and_fuel():
    app = create_app({"TESTING": True, "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:", "ENV": "development"})
    client = app.test_client()
    client.post("/auth/login", data={"username": "devadmin"})
    client.post("/transport-request/", data={"purpose": "Inspection", "travel_date": "2027-03-01", "pickup_location": "Head Office", "destination": "Pretoria", "passenger_count": "2"})
    with app.app_context():
        request_record = TransportPortalRequest.query.one()
        request_id = request_record.id
        vehicle = Vehicle(registration_number="TRN-001", fleet_number="FLT-001", current_odometer=1000, availability_status="AVAILABLE")
        driver = Driver(employee_name="Fleet Driver", employee_number="DRV-001", status="AUTHORISED")
        from smartchain.extensions import db
        db.session.add_all([vehicle, driver])
        db.session.commit()
    client.get("/auth/logout")
    client.get("/auth/dev-access")
    allocation = client.post(f"/transport/requests/{request_id}/allocate", data={"vehicle_id": "1", "driver_id": "1"}, follow_redirects=True)
    assert allocation.status_code == 200
    with app.app_context():
        transport_allocation = TransportAllocation.query.one()
        allocation_id = transport_allocation.id
        assert Vehicle.query.one().availability_status == "ALLOCATED"
    completion = client.post(f"/transport/allocations/{allocation_id}/complete", data={"odometer_end": "1125", "fuel_issued": "20", "fuel_cost": "450", "condition_notes": "Returned in good condition"}, follow_redirects=True)
    assert completion.status_code == 200
    with app.app_context():
        assert TransportAllocation.query.one().status == "COMPLETED"
        assert Vehicle.query.one().current_odometer == 1125
        assert Vehicle.query.one().availability_status == "AVAILABLE"


def test_security_and_admin_controls():
    app = create_app({"TESTING": True, "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:", "ENV": "development"})
    client = app.test_client()
    client.get("/auth/dev-access")

    security_form = client.get("/security/new")
    assert security_form.status_code == 200
    security_response = client.post(
        "/security/new",
        data={
            "severity": "High",
            "module": "Auth",
            "description": "Unexpected access attempt",
            "status": "Open",
        },
        follow_redirects=True,
    )
    assert security_response.status_code == 200
    assert b"Security event created successfully" in security_response.data

    backup_response = client.get("/admin/backups")
    assert backup_response.status_code == 200
    assert b"Backup Records" in backup_response.data


def test_approval_policy_and_archive_workflows():
    app = create_app({"TESTING": True, "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:", "ENV": "development"})
    client = app.test_client()
    client.get("/auth/dev-access")

    approval_form = client.get("/approvals/new")
    assert approval_form.status_code == 200
    approval_response = client.post(
        "/approvals/new",
        data={
            "title": "Budget approval for fleet replacement",
            "entity_type": "Demand",
            "entity_id": "1",
            "approver": "CFO / Finance Authority",
            "status": "Approved",
            "comments": "Approved within allocation limits.",
        },
        follow_redirects=True,
    )
    assert approval_response.status_code == 200
    assert b"Approval record created successfully" in approval_response.data

    policy_form = client.get("/policies/new")
    assert policy_form.status_code == 200
    policy_response = client.post(
        "/policies/new",
        data={
            "title": "Supplier Code of Conduct",
            "category": "Procurement",
            "version": "v2.1",
            "owner": "SCM Manager",
            "status": "Active",
        },
        follow_redirects=True,
    )
    assert policy_response.status_code == 200
    assert b"Policy created successfully" in policy_response.data

    archive_form = client.get("/archive/new")
    assert archive_form.status_code == 200
    archive_response = client.post(
        "/archive/new",
        data={
            "title": "FY2025 contract archive",
            "archive_type": "Contract",
            "storage_path": "archive/contracts/fy2025",
            "status": "Archived",
        },
        follow_redirects=True,
    )
    assert archive_response.status_code == 200
    assert b"Archive record created successfully" in archive_response.data


def test_performance_and_compliance_workflows_create_records():
    app = create_app({"TESTING": True, "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:", "ENV": "development"})
    client = app.test_client()
    client.get("/auth/dev-access")

    performance_form = client.get("/performance/new")
    assert performance_form.status_code == 200
    performance_response = client.post(
        "/performance/new",
        data={
            "title": "On-time procurement delivery",
            "category": "Delivery",
            "target": "95%",
            "actual": "92%",
            "status": "At Risk",
        },
        follow_redirects=True,
    )
    assert performance_response.status_code == 200
    assert b"Performance indicator created successfully" in performance_response.data

    compliance_form = client.get("/compliance/new")
    assert compliance_form.status_code == 200
    compliance_response = client.post(
        "/compliance/new",
        data={
            "title": "Bid compliance review",
            "category": "Procurement",
            "owner": "SCM Manager",
            "status": "Compliant",
            "notes": "No material deviations noted.",
        },
        follow_redirects=True,
    )
    assert compliance_response.status_code == 200
    assert b"Compliance check created successfully" in compliance_response.data


def test_budget_and_portfolio_workflows_create_records():
    app = create_app({"TESTING": True, "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:", "ENV": "development"})
    client = app.test_client()
    client.get("/auth/dev-access")

    budget_form = client.get("/budget/new")
    assert budget_form.status_code == 200
    budget_response = client.post(
        "/budget/new",
        data={
            "fiscal_year": "2027",
            "department": "Social Development",
            "allocation": "15500000",
            "expenditure": "12850000",
            "variance": "2650000",
            "status": "On Track",
        },
        follow_redirects=True,
    )
    assert budget_response.status_code == 200
    assert b"Budget forecast created successfully" in budget_response.data

    portfolio_form = client.get("/portfolio/new")
    assert portfolio_form.status_code == 200
    portfolio_response = client.post(
        "/portfolio/new",
        data={
            "project_name": "Community Outreach Modernisation",
            "phase": "Implementation",
            "owner": "Directorate: Programmes",
            "due_date": "2027-03-31",
            "completion_percent": "68",
            "status": "In Progress",
        },
        follow_redirects=True,
    )
    assert portfolio_response.status_code == 200
    assert b"Portfolio project created successfully" in portfolio_response.data


def test_strategic_planning_workflow_creates_record():
    app = create_app({"TESTING": True, "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:", "ENV": "development"})
    client = app.test_client()
    client.get("/auth/dev-access")

    plan_form = client.get("/strategic-plans/new")
    assert plan_form.status_code == 200
    plan_response = client.post(
        "/strategic-plans/new",
        data={
            "objective": "Improve integrated service delivery",
            "outcome": "Faster and more transparent beneficiary support",
            "owner": "Programme Directorate",
            "target_date": "2027-03-31",
            "progress_percent": "35",
            "status": "In Progress",
            "notes": "Quarterly outcome review scheduled.",
        },
        follow_redirects=True,
    )
    assert plan_response.status_code == 200
    assert b"Strategic plan created successfully" in plan_response.data


def test_stakeholder_and_training_workflows_create_records():
    app = create_app({"TESTING": True, "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:", "ENV": "development"})
    client = app.test_client()
    client.get("/auth/dev-access")

    stakeholder_form = client.get("/stakeholders/new")
    assert stakeholder_form.status_code == 200
    stakeholder_response = client.post(
        "/stakeholders/new",
        data={
            "name": "Amina Ndlovu",
            "organisation": "Provincial Social Services",
            "role": "Community Liaison Lead",
            "influence": "High",
            "engagement_status": "Active",
            "notes": "Quarterly briefing scheduled.",
        },
        follow_redirects=True,
    )
    assert stakeholder_response.status_code == 200
    assert b"Stakeholder created successfully" in stakeholder_response.data

    training_form = client.get("/training/new")
    assert training_form.status_code == 200
    training_response = client.post(
        "/training/new",
        data={
            "title": "Supply Chain Governance Workshop",
            "category": "Compliance",
            "provider": "National Treasury Academy",
            "target_group": "SCM Staff",
            "completion_date": "2027-02-15",
            "status": "Completed",
        },
        follow_redirects=True,
    )
    assert training_response.status_code == 200
    assert b"Training record created successfully" in training_response.data


def test_beneficiary_and_service_feedback_workflows_create_records():
    app = create_app({"TESTING": True, "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:", "ENV": "development"})
    client = app.test_client()
    client.get("/auth/dev-access")

    beneficiary_form = client.get("/beneficiaries/new")
    assert beneficiary_form.status_code == 200
    beneficiary_response = client.post(
        "/beneficiaries/new",
        data={
            "beneficiary_name": "Thabo Mokoena",
            "program": "Child Support Services",
            "location": "Johannesburg",
            "priority": "High",
            "status": "Active",
            "notes": "Needs follow-up in 2 weeks.",
        },
        follow_redirects=True,
    )
    assert beneficiary_response.status_code == 200
    assert b"Beneficiary created successfully" in beneficiary_response.data

    feedback_form = client.get("/service-feedback/new")
    assert feedback_form.status_code == 200
    feedback_response = client.post(
        "/service-feedback/new",
        data={
            "service_name": "Grant application support",
            "beneficiary_name": "Thabo Mokoena",
            "rating": "4",
            "comment": "Support was prompt and transparent.",
            "status": "Resolved",
        },
        follow_redirects=True,
    )
    assert feedback_response.status_code == 200
    assert b"Service feedback created successfully" in feedback_response.data
