import os
from flask import Flask, render_template
from flask_login import LoginManager
from sqlalchemy import inspect, text

from .config import Config
from .extensions import db, login_manager
from .models import User, Role, Permission, Department, Directorate, Unit, Employee, PasswordPolicy, DemandRequest, AnnualProcurementPlan, Requisition, ProcurementRequest, ProcurementIntakeRequest, ProcurementRequestDocument, ProcurementRequestHistory, ProcurementQuotation, ProcurementChecklistItem, ProcurementCaseEvent, ProcurementApproval, ProcurementOrder, ProcurementDelivery, Supplier, Tender, TenderProfile, TenderBidder, TenderBidderProfile, TenderCriterion, TenderCriterionConfig, TenderSubcriterion, TenderEvaluatorAssignment, EvaluatorSubcriterionScore, EvaluatorScoreRevision, TenderScreeningRequirement, TenderScreeningResult, TenderDocument, TenderStageEvent, TenderCommitteeMeeting, TenderCommitteeMember, TenderOutcome, TenderReportRecord, TenderComplianceItem, BidSubmission, EvaluatorScore, BidEvaluationCommittee, BidAdjudicationCommittee, Contract, TripRequest, Vehicle, Driver, TransportAllocation, TransportPortalRequest, TransportCaseEvent, TransportDocument, TransportAssignment, TransportMaintenance, TransportIncident, TransportTripAuthorisation, TransportVehicleIssue, TravelRequest, Asset, InternalControl, RiskRegister, AuditLog, SecurityEvent, Document, Notification, ApprovalRecord, Policy, ArchiveRecord, BackupRecord, PerformanceIndicator, ComplianceCheck, BudgetForecast, PortfolioProject, StrategicPlan, Stakeholder, TrainingRecord, Beneficiary, ServiceFeedback
from .seed import disable_all_passwords, seed_demo_data
from .utils import safe_int


def upgrade_legacy_tender_schema():
    inspector = inspect(db.engine)
    if not inspector.has_table("evaluator_score"):
        return
    existing_columns = {column["name"] for column in inspector.get_columns("evaluator_score")}
    new_columns = {
        "locked_at": "DATETIME",
        "reopened_at": "DATETIME",
        "reopen_reason": "TEXT",
    }
    for column_name, column_type in new_columns.items():
        if column_name not in existing_columns:
            db.session.execute(text(f"ALTER TABLE evaluator_score ADD COLUMN {column_name} {column_type}"))
    db.session.commit()


def create_app(test_config=None):
    app = Flask(__name__, template_folder="templates", static_folder="static")
    app.config.from_object(Config)

    if test_config:
        app.config.from_mapping(test_config)

    db.init_app(app)
    login_manager.init_app(app)

    @login_manager.user_loader
    def load_user(user_id):
        user_id = safe_int(user_id)
        return db.session.get(User, user_id) if user_id is not None else None

    with app.app_context():
        db.create_all()
        upgrade_legacy_tender_schema()
        seed_demo_data(app)
        disable_all_passwords()
        from .integrations import ensure_default_connections
        ensure_default_connections()

    @app.route("/")
    def index():
        if not app.config.get("TESTING"):
            if app.config["ENV"] == "production":
                return render_template("landing.html", app_name="SmartChain")
        return render_template("landing.html", app_name="SmartChain")

    from .integrations import integration_bp
    from .routes import auth_bp, org_bp, dashboard_bp, demand_bp, app_bp, requisition_bp, procurement_bp, procurement_portal_bp, procurement_intake_bp, internal_control_procurement_bp, supplier_bp, tender_bp, bec_bp, bac_bp, contract_bp, transport_bp, transport_portal_bp, travel_bp, asset_bp, control_bp, risk_bp, audit_bp, report_bp, security_bp, document_bp, notification_bp, search_bp, admin_bp, approval_bp, policy_bp, archive_bp, performance_bp, compliance_bp, budget_bp, portfolio_bp, strategic_plans_bp, stakeholders_bp, training_bp, beneficiaries_bp, service_feedback_bp
    app.register_blueprint(auth_bp)
    app.register_blueprint(org_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(demand_bp)
    app.register_blueprint(app_bp)
    app.register_blueprint(requisition_bp)
    app.register_blueprint(procurement_bp)
    app.register_blueprint(procurement_portal_bp)
    app.register_blueprint(procurement_intake_bp)
    app.register_blueprint(internal_control_procurement_bp)
    app.register_blueprint(supplier_bp)
    app.register_blueprint(tender_bp)
    app.register_blueprint(bec_bp)
    app.register_blueprint(bac_bp)
    app.register_blueprint(contract_bp)
    app.register_blueprint(transport_bp)
    app.register_blueprint(transport_portal_bp)
    app.register_blueprint(travel_bp)
    app.register_blueprint(asset_bp)
    app.register_blueprint(control_bp)
    app.register_blueprint(risk_bp)
    app.register_blueprint(audit_bp)
    app.register_blueprint(report_bp)
    app.register_blueprint(security_bp)
    app.register_blueprint(document_bp)
    app.register_blueprint(notification_bp)
    app.register_blueprint(search_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(approval_bp)
    app.register_blueprint(policy_bp)
    app.register_blueprint(archive_bp)
    app.register_blueprint(performance_bp)
    app.register_blueprint(compliance_bp)
    app.register_blueprint(budget_bp)
    app.register_blueprint(portfolio_bp)
    app.register_blueprint(strategic_plans_bp)
    app.register_blueprint(stakeholders_bp)
    app.register_blueprint(training_bp)
    app.register_blueprint(beneficiaries_bp)
    app.register_blueprint(service_feedback_bp)
    app.register_blueprint(integration_bp)

    return app
