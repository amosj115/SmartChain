from datetime import datetime

from flask_login import UserMixin

from .extensions import db


class Role(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), unique=True, nullable=False)
    description = db.Column(db.Text)
    users = db.relationship("User", back_populates="role_obj", lazy=True)
    permissions = db.relationship("Permission", back_populates="role", lazy=True)


class Permission(db.Model):
    __table_args__ = (db.UniqueConstraint("role_id", "name", name="uq_role_permission"),)
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    role_id = db.Column(db.Integer, db.ForeignKey("role.id"), nullable=True)
    role = db.relationship("Role", back_populates="permissions")


class Department(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), unique=True, nullable=False)
    code = db.Column(db.String(50), unique=True, nullable=False)
    description = db.Column(db.Text)
    directorates = db.relationship("Directorate", back_populates="department", lazy=True)
    employees = db.relationship("Employee", back_populates="department", lazy=True)


class Directorate(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    code = db.Column(db.String(50), nullable=False)
    department_id = db.Column(db.Integer, db.ForeignKey("department.id"), nullable=False)
    department = db.relationship("Department", back_populates="directorates")
    units = db.relationship("Unit", back_populates="directorate", lazy=True)
    employees = db.relationship("Employee", back_populates="directorate", lazy=True)


class Unit(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    code = db.Column(db.String(50), nullable=False)
    directorate_id = db.Column(db.Integer, db.ForeignKey("directorate.id"), nullable=False)
    directorate = db.relationship("Directorate", back_populates="units")
    employees = db.relationship("Employee", back_populates="unit", lazy=True)


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    full_name = db.Column(db.String(200), nullable=False)
    password_hash = db.Column(db.String(255), nullable=True)
    is_active = db.Column(db.Boolean, default=True)
    role_id = db.Column(db.Integer, db.ForeignKey("role.id"), nullable=False)
    employee_id = db.Column(db.Integer, db.ForeignKey("employee.id"), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login_at = db.Column(db.DateTime, nullable=True)
    role_obj = db.relationship("Role", back_populates="users")
    employee = db.relationship("Employee", back_populates="user", uselist=False)

    def set_password(self, password):
        from werkzeug.security import generate_password_hash

        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        from werkzeug.security import check_password_hash

        if not self.password_hash:
            return False
        return check_password_hash(self.password_hash, password)


class PasswordPolicy(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), unique=True, nullable=False)
    must_change_password = db.Column(db.Boolean, default=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow)
    user = db.relationship("User", backref=db.backref("password_policy", uselist=False))


class Employee(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    employee_number = db.Column(db.String(50), unique=True, nullable=False)
    first_name = db.Column(db.String(120), nullable=False)
    last_name = db.Column(db.String(120), nullable=False)
    title = db.Column(db.String(120), nullable=True)
    position = db.Column(db.String(200), nullable=True)
    email = db.Column(db.String(120), nullable=True)
    phone = db.Column(db.String(50), nullable=True)
    department_id = db.Column(db.Integer, db.ForeignKey("department.id"), nullable=False)
    directorate_id = db.Column(db.Integer, db.ForeignKey("directorate.id"), nullable=False)
    unit_id = db.Column(db.Integer, db.ForeignKey("unit.id"), nullable=False)
    role_id = db.Column(db.Integer, db.ForeignKey("role.id"), nullable=False)
    account_status = db.Column(db.String(50), default="active")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    department = db.relationship("Department", back_populates="employees")
    directorate = db.relationship("Directorate", back_populates="employees")
    unit = db.relationship("Unit", back_populates="employees")
    role = db.relationship("Role")
    user = db.relationship("User", back_populates="employee", uselist=False)


class DemandRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=False)
    responsible_unit = db.Column(db.String(120), nullable=True)
    estimated_cost = db.Column(db.Float, default=0.0)
    priority = db.Column(db.String(50), default="Medium")
    timing = db.Column(db.String(120), nullable=True)
    status = db.Column(db.String(50), default="Draft")
    justification = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class AnnualProcurementPlan(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    item_name = db.Column(db.String(200), nullable=False)
    estimated_value = db.Column(db.Float, default=0.0)
    procurement_method = db.Column(db.String(80), default="Open Tender")
    responsible_unit = db.Column(db.String(120), nullable=True)
    planned_date = db.Column(db.String(50), nullable=True)
    budget_allocation = db.Column(db.Float, default=0.0)
    status = db.Column(db.String(50), default="Planned")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class Requisition(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    requisition_number = db.Column(db.String(50), unique=True, nullable=False)
    requester = db.Column(db.String(200), nullable=False)
    department = db.Column(db.String(120), nullable=False)
    directorate = db.Column(db.String(120), nullable=True)
    unit = db.Column(db.String(120), nullable=True)
    description = db.Column(db.Text, nullable=False)
    motivation = db.Column(db.Text, nullable=True)
    estimated_value = db.Column(db.Float, default=0.0)
    budget = db.Column(db.String(100), nullable=True)
    priority = db.Column(db.String(50), default="Medium")
    status = db.Column(db.String(50), default="Submitted")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class ProcurementRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    procurement_method = db.Column(db.String(80), default="Open Tender")
    estimated_value = db.Column(db.Float, default=0.0)
    status = db.Column(db.String(50), default="Draft")
    recommendation = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class ProcurementIntakeRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    request_number = db.Column(db.String(50), unique=True, nullable=False)
    requester_user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    employee_name = db.Column(db.String(200), nullable=False)
    employee_number = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(120), nullable=True)
    contact_number = db.Column(db.String(50), nullable=True)
    directorate = db.Column(db.String(200), nullable=True)
    chief_directorate = db.Column(db.String(200), nullable=True)
    unit = db.Column(db.String(200), nullable=True)
    job_title = db.Column(db.String(200), nullable=True)
    cost_centre = db.Column(db.String(100), nullable=True)
    required_by_date = db.Column(db.String(50), nullable=True)
    procurement_category = db.Column(db.String(120), nullable=True)
    procurement_type = db.Column(db.String(80), nullable=False)
    description = db.Column(db.Text, nullable=False)
    specification = db.Column(db.Text, nullable=True)
    quantity = db.Column(db.Integer, default=1)
    estimated_value = db.Column(db.Float, default=0.0)
    business_need = db.Column(db.Text, nullable=True)
    justification = db.Column(db.Text, nullable=True)
    delivery_location = db.Column(db.String(200), nullable=True)
    responsible_official = db.Column(db.String(200), nullable=True)
    status = db.Column(db.String(80), default="Submitted")
    assigned_user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)
    scm_notes = db.Column(db.Text, nullable=True)
    internal_control_notes = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    requester = db.relationship("User", foreign_keys=[requester_user_id], backref=db.backref("procurement_intake_requests", lazy=True))
    assigned_user = db.relationship("User", foreign_keys=[assigned_user_id])
    documents = db.relationship("ProcurementRequestDocument", back_populates="request", cascade="all, delete-orphan", lazy=True)
    history = db.relationship("ProcurementRequestHistory", back_populates="request", cascade="all, delete-orphan", order_by="ProcurementRequestHistory.created_at", lazy=True)
    quotations = db.relationship("ProcurementQuotation", back_populates="request", cascade="all, delete-orphan", lazy=True)


class ProcurementRequestDocument(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    request_id = db.Column(db.Integer, db.ForeignKey("procurement_intake_request.id"), nullable=False)
    category = db.Column(db.String(120), nullable=False)
    title = db.Column(db.String(200), nullable=False)
    file_name = db.Column(db.String(255), nullable=True)
    storage_path = db.Column(db.String(500), nullable=True)
    uploaded_by_user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    request = db.relationship("ProcurementIntakeRequest", back_populates="documents")
    uploaded_by = db.relationship("User")


class ProcurementRequestHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    request_id = db.Column(db.Integer, db.ForeignKey("procurement_intake_request.id"), nullable=False)
    action = db.Column(db.String(120), nullable=False)
    from_status = db.Column(db.String(80), nullable=True)
    to_status = db.Column(db.String(80), nullable=True)
    comment = db.Column(db.Text, nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    request = db.relationship("ProcurementIntakeRequest", back_populates="history")
    user = db.relationship("User")


class ProcurementQuotation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    request_id = db.Column(db.Integer, db.ForeignKey("procurement_intake_request.id"), nullable=False)
    supplier_name = db.Column(db.String(200), nullable=False)
    quotation_date = db.Column(db.String(50), nullable=True)
    amount = db.Column(db.Float, default=0.0)
    response_status = db.Column(db.String(50), default="Received")
    compliance_notes = db.Column(db.Text, nullable=True)
    created_by_user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    request = db.relationship("ProcurementIntakeRequest", back_populates="quotations")
    created_by = db.relationship("User")


class ProcurementChecklistItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    request_id = db.Column(db.Integer, db.ForeignKey("procurement_intake_request.id"), nullable=False)
    name = db.Column(db.String(200), nullable=False)
    required = db.Column(db.Boolean, default=True, nullable=False)
    status = db.Column(db.String(50), default="PENDING", nullable=False)
    reason = db.Column(db.Text, nullable=True)
    evidence_reference = db.Column(db.String(240), nullable=True)
    reviewed_by_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)
    reviewed_at = db.Column(db.DateTime, nullable=True)
    request = db.relationship("ProcurementIntakeRequest", backref=db.backref("checklist_items", cascade="all, delete-orphan"))
    reviewed_by = db.relationship("User")


class ProcurementCaseEvent(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    request_id = db.Column(db.Integer, db.ForeignKey("procurement_intake_request.id"), nullable=False)
    action = db.Column(db.String(120), nullable=False)
    from_status = db.Column(db.String(80), nullable=True)
    to_status = db.Column(db.String(80), nullable=True)
    comment = db.Column(db.Text, nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    role_name = db.Column(db.String(120), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    request = db.relationship("ProcurementIntakeRequest", backref=db.backref("case_events", cascade="all, delete-orphan", order_by="ProcurementCaseEvent.created_at"))
    user = db.relationship("User")


class ProcurementApproval(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    request_id = db.Column(db.Integer, db.ForeignKey("procurement_intake_request.id"), nullable=False)
    status = db.Column(db.String(50), default="PENDING", nullable=False)
    decision = db.Column(db.Text, nullable=True)
    approver_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    decided_at = db.Column(db.DateTime, nullable=True)
    request = db.relationship("ProcurementIntakeRequest", backref=db.backref("procurement_approvals", cascade="all, delete-orphan"))
    approver = db.relationship("User")


class ProcurementOrder(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    request_id = db.Column(db.Integer, db.ForeignKey("procurement_intake_request.id"), nullable=False)
    order_reference = db.Column(db.String(100), unique=True, nullable=False)
    supplier_name = db.Column(db.String(200), nullable=False)
    amount = db.Column(db.Float, default=0.0)
    status = db.Column(db.String(50), default="OPEN")
    created_by_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    request = db.relationship("ProcurementIntakeRequest", backref=db.backref("procurement_orders", lazy=True))
    created_by = db.relationship("User")


class ProcurementDelivery(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    request_id = db.Column(db.Integer, db.ForeignKey("procurement_intake_request.id"), nullable=False)
    status = db.Column(db.String(50), default="PENDING", nullable=False)
    quantity = db.Column(db.Integer, default=0)
    received_by_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)
    received_at = db.Column(db.DateTime, nullable=True)
    comments = db.Column(db.Text, nullable=True)
    request = db.relationship("ProcurementIntakeRequest", backref=db.backref("deliveries", lazy=True))
    received_by = db.relationship("User")


class Supplier(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    registration_number = db.Column(db.String(100), unique=True, nullable=False)
    service_categories = db.Column(db.Text)
    status = db.Column(db.String(50), default="Active")
    contact_email = db.Column(db.String(120), nullable=True)
    phone = db.Column(db.String(50), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class Tender(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    tender_number = db.Column(db.String(50), unique=True, nullable=False)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=True)
    estimated_value = db.Column(db.Float, default=0.0)
    closing_date = db.Column(db.String(50), nullable=True)
    status = db.Column(db.String(50), default="Open")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    bidders = db.relationship("TenderBidder", back_populates="tender", cascade="all, delete-orphan", lazy=True)
    criteria = db.relationship("TenderCriterion", back_populates="tender", cascade="all, delete-orphan", lazy=True)
    evaluations = db.relationship("EvaluatorScore", back_populates="tender", cascade="all, delete-orphan", lazy=True)
    bec_records = db.relationship("BidEvaluationCommittee", back_populates="tender", lazy=True)
    bac_records = db.relationship("BidAdjudicationCommittee", back_populates="tender", lazy=True)


class TenderProfile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    tender_id = db.Column(db.Integer, db.ForeignKey("tender.id"), unique=True, nullable=False)
    directorate = db.Column(db.String(160), nullable=True)
    responsible_official = db.Column(db.String(200), nullable=True)
    procurement_category = db.Column(db.String(120), nullable=True)
    procurement_type = db.Column(db.String(80), nullable=True)
    opening_date = db.Column(db.String(50), nullable=True)
    evaluation_methodology = db.Column(db.String(200), nullable=True)
    mandatory_requirements = db.Column(db.Text, nullable=True)
    functionality_required = db.Column(db.Boolean, default=False, nullable=False)
    price_preference_method = db.Column(db.String(200), nullable=True)
    minimum_functionality_threshold = db.Column(db.Float, nullable=True)
    tender = db.relationship("Tender", backref=db.backref("profile", uselist=False, cascade="all, delete-orphan"))


class TenderBidder(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    tender_id = db.Column(db.Integer, db.ForeignKey("tender.id"), nullable=False)
    legal_name = db.Column(db.String(200), nullable=False)
    supplier_reference = db.Column(db.String(100), nullable=True)
    registration_details = db.Column(db.Text, nullable=True)
    submitted_at = db.Column(db.DateTime, nullable=True)
    bid_price = db.Column(db.Float, default=0.0)
    compliance_status = db.Column(db.String(50), default="Pending")
    evaluation_status = db.Column(db.String(50), default="Not Started")
    disqualification_reason = db.Column(db.Text, nullable=True)
    comments = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    tender = db.relationship("Tender", back_populates="bidders")


class TenderBidderProfile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    bidder_id = db.Column(db.Integer, db.ForeignKey("tender_bidder.id"), unique=True, nullable=False)
    trading_name = db.Column(db.String(200), nullable=True)
    registration_number = db.Column(db.String(100), nullable=True)
    contact_name = db.Column(db.String(200), nullable=True)
    contact_email = db.Column(db.String(160), nullable=True)
    phone = db.Column(db.String(80), nullable=True)
    bidder = db.relationship("TenderBidder", backref=db.backref("profile", uselist=False, cascade="all, delete-orphan"))


class TenderCriterion(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    tender_id = db.Column(db.Integer, db.ForeignKey("tender.id"), nullable=False)
    name = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=True)
    weight = db.Column(db.Float, default=0.0)
    max_score = db.Column(db.Integer, default=5)
    scoring_framework = db.Column(db.String(50), default="1-5")
    pass_fail = db.Column(db.Boolean, default=False)
    instructions = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    tender = db.relationship("Tender", back_populates="criteria")
    evaluations = db.relationship("EvaluatorScore", back_populates="criterion", cascade="all, delete-orphan", lazy=True)


class TenderComplianceItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    tender_id = db.Column(db.Integer, db.ForeignKey("tender.id"), nullable=False)
    requirement = db.Column(db.String(240), nullable=False)
    submitted = db.Column(db.Boolean, default=False)
    valid = db.Column(db.Boolean, nullable=True)
    notes = db.Column(db.Text, nullable=True)
    evidence_reference = db.Column(db.String(240), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    tender = db.relationship("Tender", backref=db.backref("compliance_items", lazy=True))


class BidSubmission(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    tender_id = db.Column(db.Integer, db.ForeignKey("tender.id"), nullable=False)
    bidder_id = db.Column(db.Integer, db.ForeignKey("tender_bidder.id"), nullable=False)
    document_category = db.Column(db.String(100), nullable=False)
    document_title = db.Column(db.String(200), nullable=False)
    document_reference = db.Column(db.String(240), nullable=True)
    submitted_at = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(50), default="Received")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    tender = db.relationship("Tender", backref=db.backref("bid_submissions", lazy=True))
    bidder = db.relationship("TenderBidder", backref=db.backref("submissions", lazy=True))


class EvaluatorScore(db.Model):
    __table_args__ = (db.UniqueConstraint("tender_id", "bidder_id", "criterion_id", "evaluator_id", name="uq_evaluator_score"),)
    id = db.Column(db.Integer, primary_key=True)
    tender_id = db.Column(db.Integer, db.ForeignKey("tender.id"), nullable=False)
    bidder_id = db.Column(db.Integer, db.ForeignKey("tender_bidder.id"), nullable=False)
    criterion_id = db.Column(db.Integer, db.ForeignKey("tender_criterion.id"), nullable=False)
    evaluator_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    score = db.Column(db.Float, nullable=True)
    comments = db.Column(db.Text, nullable=True)
    status = db.Column(db.String(50), default="Draft")
    submitted_at = db.Column(db.DateTime, nullable=True)
    locked_at = db.Column(db.DateTime, nullable=True)
    reopened_at = db.Column(db.DateTime, nullable=True)
    reopen_reason = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    tender = db.relationship("Tender", back_populates="evaluations")
    bidder = db.relationship("TenderBidder", backref="evaluations")
    criterion = db.relationship("TenderCriterion", back_populates="evaluations")
    evaluator = db.relationship("User")


class TenderCriterionConfig(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    criterion_id = db.Column(db.Integer, db.ForeignKey("tender_criterion.id"), unique=True, nullable=False)
    category = db.Column(db.String(100), nullable=True)
    minimum_qualifying_score = db.Column(db.Float, nullable=True)
    mandatory = db.Column(db.Boolean, default=False, nullable=False)
    evidence_required = db.Column(db.Text, nullable=True)
    position = db.Column(db.Integer, default=0, nullable=False)
    criterion = db.relationship("TenderCriterion", backref=db.backref("config", uselist=False, cascade="all, delete-orphan"))


class TenderSubcriterion(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    criterion_id = db.Column(db.Integer, db.ForeignKey("tender_criterion.id"), nullable=False)
    name = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=True)
    max_points = db.Column(db.Float, nullable=False)
    position = db.Column(db.Integer, default=0, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    criterion = db.relationship("TenderCriterion", backref=db.backref("subcriteria", cascade="all, delete-orphan", order_by="TenderSubcriterion.position"))


class TenderEvaluatorAssignment(db.Model):
    __table_args__ = (db.UniqueConstraint("tender_id", "user_id", name="uq_tender_evaluator_assignment"),)
    id = db.Column(db.Integer, primary_key=True)
    tender_id = db.Column(db.Integer, db.ForeignKey("tender.id"), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    assigned_by_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    active = db.Column(db.Boolean, default=True, nullable=False)
    assigned_at = db.Column(db.DateTime, default=datetime.utcnow)
    tender = db.relationship("Tender", backref=db.backref("evaluator_assignments", cascade="all, delete-orphan"))
    user = db.relationship("User", foreign_keys=[user_id])
    assigned_by = db.relationship("User", foreign_keys=[assigned_by_id])


class EvaluatorSubcriterionScore(db.Model):
    __table_args__ = (db.UniqueConstraint("evaluation_id", "subcriterion_id", name="uq_evaluator_subcriterion_score"),)
    id = db.Column(db.Integer, primary_key=True)
    evaluation_id = db.Column(db.Integer, db.ForeignKey("evaluator_score.id"), nullable=False)
    subcriterion_id = db.Column(db.Integer, db.ForeignKey("tender_subcriterion.id"), nullable=False)
    score = db.Column(db.Float, nullable=False)
    comments = db.Column(db.Text, nullable=True)
    evidence_reference = db.Column(db.String(240), nullable=True)
    evaluation = db.relationship("EvaluatorScore", backref=db.backref("subcriterion_scores", cascade="all, delete-orphan"))
    subcriterion = db.relationship("TenderSubcriterion")


class EvaluatorScoreRevision(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    evaluation_id = db.Column(db.Integer, db.ForeignKey("evaluator_score.id"), nullable=False)
    reopened_by_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    reason = db.Column(db.Text, nullable=False)
    previous_score = db.Column(db.Float, nullable=True)
    previous_comments = db.Column(db.Text, nullable=True)
    previous_status = db.Column(db.String(50), nullable=False)
    previous_subcriteria = db.Column(db.Text, nullable=True)
    reopened_at = db.Column(db.DateTime, default=datetime.utcnow)
    evaluation = db.relationship("EvaluatorScore", backref=db.backref("revisions", cascade="all, delete-orphan"))
    reopened_by = db.relationship("User")


class TenderScreeningRequirement(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    tender_id = db.Column(db.Integer, db.ForeignKey("tender.id"), nullable=False)
    name = db.Column(db.String(240), nullable=False)
    category = db.Column(db.String(100), nullable=True)
    mandatory = db.Column(db.Boolean, default=True, nullable=False)
    position = db.Column(db.Integer, default=0, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    tender = db.relationship("Tender", backref=db.backref("screening_requirements", cascade="all, delete-orphan"))


class TenderScreeningResult(db.Model):
    __table_args__ = (db.UniqueConstraint("requirement_id", "bidder_id", name="uq_tender_screening_result"),)
    id = db.Column(db.Integer, primary_key=True)
    requirement_id = db.Column(db.Integer, db.ForeignKey("tender_screening_requirement.id"), nullable=False)
    bidder_id = db.Column(db.Integer, db.ForeignKey("tender_bidder.id"), nullable=False)
    result = db.Column(db.String(30), default="PENDING", nullable=False)
    evidence_reference = db.Column(db.String(240), nullable=True)
    comments = db.Column(db.Text, nullable=True)
    reviewer_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)
    reviewed_at = db.Column(db.DateTime, nullable=True)
    requirement = db.relationship("TenderScreeningRequirement", backref=db.backref("results", cascade="all, delete-orphan"))
    bidder = db.relationship("TenderBidder", backref=db.backref("screening_results", cascade="all, delete-orphan"))
    reviewer = db.relationship("User")


class TenderDocument(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    tender_id = db.Column(db.Integer, db.ForeignKey("tender.id"), nullable=False)
    category = db.Column(db.String(100), nullable=False)
    original_filename = db.Column(db.String(255), nullable=False)
    stored_filename = db.Column(db.String(255), nullable=False)
    version = db.Column(db.Integer, default=1, nullable=False)
    description = db.Column(db.Text, nullable=True)
    uploaded_by_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow)
    tender = db.relationship("Tender", backref=db.backref("documents", cascade="all, delete-orphan"))
    uploaded_by = db.relationship("User")


class TenderStageEvent(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    tender_id = db.Column(db.Integer, db.ForeignKey("tender.id"), nullable=False)
    stage = db.Column(db.String(50), nullable=False)
    status = db.Column(db.String(50), nullable=False)
    details = db.Column(db.Text, nullable=True)
    document_reference = db.Column(db.String(240), nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)
    occurred_at = db.Column(db.DateTime, default=datetime.utcnow)
    tender = db.relationship("Tender", backref=db.backref("timeline_events", cascade="all, delete-orphan"))
    user = db.relationship("User")


class TenderCommitteeMeeting(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    tender_id = db.Column(db.Integer, db.ForeignKey("tender.id"), nullable=False)
    committee_type = db.Column(db.String(10), nullable=False)
    meeting_number = db.Column(db.String(80), nullable=True)
    meeting_at = db.Column(db.DateTime, nullable=True)
    venue = db.Column(db.String(200), nullable=True)
    chair = db.Column(db.String(200), nullable=True)
    secretariat = db.Column(db.String(200), nullable=True)
    agenda_reference = db.Column(db.String(240), nullable=True)
    minutes = db.Column(db.Text, nullable=True)
    resolution = db.Column(db.Text, nullable=True)
    status = db.Column(db.String(50), default="Planned")
    created_by_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    tender = db.relationship("Tender", backref=db.backref("committee_meetings", cascade="all, delete-orphan"))
    created_by = db.relationship("User")


class TenderCommitteeMember(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    meeting_id = db.Column(db.Integer, db.ForeignKey("tender_committee_meeting.id"), nullable=False)
    name = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(100), nullable=True)
    organization = db.Column(db.String(200), nullable=True)
    attended = db.Column(db.Boolean, nullable=True)
    meeting = db.relationship("TenderCommitteeMeeting", backref=db.backref("members", cascade="all, delete-orphan"))


class TenderOutcome(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    tender_id = db.Column(db.Integer, db.ForeignKey("tender.id"), nullable=False)
    status = db.Column(db.String(50), nullable=False)
    decision_type = db.Column(db.String(50), nullable=False)
    bidder_id = db.Column(db.Integer, db.ForeignKey("tender_bidder.id"), nullable=True)
    rationale = db.Column(db.Text, nullable=False)
    decided_by_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    decided_at = db.Column(db.DateTime, default=datetime.utcnow)
    tender = db.relationship("Tender", backref=db.backref("outcomes", cascade="all, delete-orphan"))
    bidder = db.relationship("TenderBidder")
    decided_by = db.relationship("User")


class TenderReportRecord(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    tender_id = db.Column(db.Integer, db.ForeignKey("tender.id"), nullable=False)
    committee_type = db.Column(db.String(10), nullable=False)
    version = db.Column(db.Integer, nullable=False)
    report_reference = db.Column(db.String(240), nullable=False)
    generated_by_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    generated_at = db.Column(db.DateTime, default=datetime.utcnow)
    tender = db.relationship("Tender", backref=db.backref("generated_reports", cascade="all, delete-orphan"))
    generated_by = db.relationship("User")


class BidEvaluationCommittee(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    tender_id = db.Column(db.Integer, db.ForeignKey("tender.id"), nullable=False)
    title = db.Column(db.String(200), nullable=False)
    evaluation_status = db.Column(db.String(50), default="In Progress")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    tender = db.relationship("Tender", back_populates="bec_records")


class BidAdjudicationCommittee(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    tender_id = db.Column(db.Integer, db.ForeignKey("tender.id"), nullable=False)
    title = db.Column(db.String(200), nullable=False)
    decision = db.Column(db.String(120), nullable=True)
    status = db.Column(db.String(50), default="Pending")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    tender = db.relationship("Tender", back_populates="bac_records")


class Contract(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    contract_number = db.Column(db.String(50), unique=True, nullable=False)
    supplier = db.Column(db.String(200), nullable=False)
    tender = db.Column(db.String(200), nullable=True)
    start_date = db.Column(db.String(50), nullable=True)
    end_date = db.Column(db.String(50), nullable=True)
    value = db.Column(db.Float, default=0.0)
    status = db.Column(db.String(50), default="Active")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class TripRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    origin = db.Column(db.String(200), nullable=False)
    destination = db.Column(db.String(200), nullable=False)
    purpose = db.Column(db.Text, nullable=True)
    status = db.Column(db.String(50), default="Requested")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class Vehicle(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    registration_number = db.Column(db.String(50), unique=True, nullable=False)
    fleet_number = db.Column(db.String(50), unique=True, nullable=False)
    make = db.Column(db.String(100), nullable=True)
    model = db.Column(db.String(100), nullable=True)
    vehicle_type = db.Column(db.String(100), nullable=True)
    fuel_type = db.Column(db.String(50), nullable=True)
    fuel_capacity = db.Column(db.Float, default=0.0)
    current_odometer = db.Column(db.Integer, default=0)
    current_location = db.Column(db.String(200), nullable=True)
    availability_status = db.Column(db.String(50), default="AVAILABLE")
    service_status = db.Column(db.String(80), default="In Service")
    next_service = db.Column(db.String(50), nullable=True)
    condition = db.Column(db.String(80), default="Good")
    notes = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class Driver(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    employee_name = db.Column(db.String(200), nullable=False)
    employee_number = db.Column(db.String(50), nullable=False)
    contact = db.Column(db.String(100), nullable=True)
    licence_number = db.Column(db.String(100), nullable=True)
    licence_expiry = db.Column(db.String(50), nullable=True)
    status = db.Column(db.String(50), default="AUTHORISED")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class TransportAllocation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    transport_request_id = db.Column(db.Integer, db.ForeignKey("transport_portal_request.id"), nullable=False)
    vehicle_id = db.Column(db.Integer, db.ForeignKey("vehicle.id"), nullable=False)
    driver_id = db.Column(db.Integer, db.ForeignKey("driver.id"), nullable=True)
    status = db.Column(db.String(50), default="ALLOCATED")
    odometer_start = db.Column(db.Integer, nullable=True)
    odometer_end = db.Column(db.Integer, nullable=True)
    fuel_issued = db.Column(db.Float, nullable=True)
    fuel_cost = db.Column(db.Float, nullable=True)
    condition_notes = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    returned_at = db.Column(db.DateTime, nullable=True)
    transport_request = db.relationship("TransportPortalRequest", backref=db.backref("allocation", uselist=False))
    vehicle = db.relationship("Vehicle")
    driver = db.relationship("Driver")


class TransportPortalRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    requester_user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    employee_name = db.Column(db.String(200), nullable=False)
    employee_number = db.Column(db.String(50), nullable=False)
    directorate = db.Column(db.String(200), nullable=True)
    unit = db.Column(db.String(200), nullable=True)
    contact_details = db.Column(db.String(200), nullable=True)
    purpose = db.Column(db.Text, nullable=False)
    travel_date = db.Column(db.String(50), nullable=False)
    departure_time = db.Column(db.String(20), nullable=True)
    return_time = db.Column(db.String(20), nullable=True)
    pickup_location = db.Column(db.String(200), nullable=False)
    destination = db.Column(db.String(200), nullable=False)
    passenger_count = db.Column(db.Integer, default=1)
    additional_stops = db.Column(db.Text, nullable=True)
    special_requirements = db.Column(db.Text, nullable=True)
    status = db.Column(db.String(50), default="Submitted")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    requester = db.relationship("User", backref=db.backref("transport_portal_requests", lazy=True))


class TransportCaseEvent(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    transport_request_id = db.Column(db.Integer, db.ForeignKey("transport_portal_request.id"), nullable=False)
    action = db.Column(db.String(120), nullable=False)
    previous_status = db.Column(db.String(80), nullable=True)
    new_status = db.Column(db.String(80), nullable=True)
    comment = db.Column(db.Text, nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)
    role_name = db.Column(db.String(120), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    transport_request = db.relationship("TransportPortalRequest", backref=db.backref("case_events", cascade="all, delete-orphan", order_by="TransportCaseEvent.created_at"))
    user = db.relationship("User")


class TransportDocument(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    transport_request_id = db.Column(db.Integer, db.ForeignKey("transport_portal_request.id"), nullable=False)
    document_type = db.Column(db.String(120), nullable=False)
    original_filename = db.Column(db.String(255), nullable=False)
    version = db.Column(db.Integer, default=1, nullable=False)
    storage_path = db.Column(db.String(500), nullable=False)
    uploaded_by_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow)
    transport_request = db.relationship("TransportPortalRequest", backref=db.backref("transport_documents", cascade="all, delete-orphan"))
    uploaded_by = db.relationship("User")


class TransportAssignment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    transport_request_id = db.Column(db.Integer, db.ForeignKey("transport_portal_request.id"), nullable=False, unique=True)
    official_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)
    unit = db.Column(db.String(160), nullable=True)
    stage = db.Column(db.String(100), nullable=False, default="Central Intake")
    assigned_by_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)
    assigned_at = db.Column(db.DateTime, default=datetime.utcnow)
    transport_request = db.relationship("TransportPortalRequest", backref=db.backref("transport_assignment", uselist=False, cascade="all, delete-orphan"))
    official = db.relationship("User", foreign_keys=[official_id])
    assigned_by = db.relationship("User", foreign_keys=[assigned_by_id])


class TransportMaintenance(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    vehicle_id = db.Column(db.Integer, db.ForeignKey("vehicle.id"), nullable=False)
    status = db.Column(db.String(50), nullable=False, default="OPEN")
    maintenance_type = db.Column(db.String(120), nullable=False)
    description = db.Column(db.Text, nullable=True)
    cost = db.Column(db.Float, default=0.0)
    vendor = db.Column(db.String(200), nullable=True)
    opened_at = db.Column(db.DateTime, default=datetime.utcnow)
    completed_at = db.Column(db.DateTime, nullable=True)
    vehicle = db.relationship("Vehicle", backref=db.backref("maintenance_records", lazy=True))


class TransportIncident(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    transport_request_id = db.Column(db.Integer, db.ForeignKey("transport_portal_request.id"), nullable=False)
    vehicle_id = db.Column(db.Integer, db.ForeignKey("vehicle.id"), nullable=True)
    driver_id = db.Column(db.Integer, db.ForeignKey("driver.id"), nullable=True)
    incident_type = db.Column(db.String(120), nullable=False)
    description = db.Column(db.Text, nullable=False)
    location = db.Column(db.String(200), nullable=True)
    damage = db.Column(db.Text, nullable=True)
    status = db.Column(db.String(50), default="OPEN")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    transport_request = db.relationship("TransportPortalRequest", backref=db.backref("incidents", lazy=True))
    vehicle = db.relationship("Vehicle")
    driver = db.relationship("Driver")


class TransportTripAuthorisation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    transport_request_id = db.Column(db.Integer, db.ForeignKey("transport_portal_request.id"), nullable=False)
    allocation_id = db.Column(db.Integer, db.ForeignKey("transport_allocation.id"), nullable=False)
    status = db.Column(db.String(50), default="AUTHORISED")
    authorised_by_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    version = db.Column(db.Integer, default=1, nullable=False)
    generated_at = db.Column(db.DateTime, default=datetime.utcnow)
    transport_request = db.relationship("TransportPortalRequest", backref=db.backref("trip_authorisations", lazy=True))
    allocation = db.relationship("TransportAllocation")
    authorised_by = db.relationship("User")


class TransportVehicleIssue(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    allocation_id = db.Column(db.Integer, db.ForeignKey("transport_allocation.id"), nullable=False, unique=True)
    issued_by_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    issued_at = db.Column(db.DateTime, default=datetime.utcnow)
    odometer = db.Column(db.Integer, nullable=False)
    fuel_level = db.Column(db.Float, nullable=True)
    condition = db.Column(db.String(120), nullable=True)
    accessories = db.Column(db.Text, nullable=True)
    acknowledgement = db.Column(db.Text, nullable=True)
    allocation = db.relationship("TransportAllocation", backref=db.backref("vehicle_issue", uselist=False))
    issued_by = db.relationship("User")


class TravelRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    purpose = db.Column(db.Text, nullable=False)
    destination = db.Column(db.String(200), nullable=True)
    status = db.Column(db.String(50), default="Draft")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class Asset(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    asset_number = db.Column(db.String(50), unique=True, nullable=False)
    description = db.Column(db.String(200), nullable=False)
    category = db.Column(db.String(100), nullable=True)
    location = db.Column(db.String(120), nullable=True)
    value = db.Column(db.Float, default=0.0)
    condition = db.Column(db.String(50), default="Good")
    status = db.Column(db.String(50), default="Active")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class InternalControl(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    control_objective = db.Column(db.String(200), nullable=False)
    process_name = db.Column(db.String(120), nullable=True)
    risk_rating = db.Column(db.String(50), default="Medium")
    status = db.Column(db.String(50), default="Active")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class RiskRegister(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    category = db.Column(db.String(120), nullable=True)
    likelihood = db.Column(db.String(50), default="Medium")
    impact = db.Column(db.String(50), default="Medium")
    risk_rating = db.Column(db.String(50), default="Moderate")
    status = db.Column(db.String(50), default="Open")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    module = db.Column(db.String(120), nullable=False)
    action = db.Column(db.String(120), nullable=False)
    entity = db.Column(db.String(120), nullable=False)
    details = db.Column(db.Text, nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class IntegrationConnection(db.Model):
    __tablename__ = "integration_connections"
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(50), unique=True, nullable=False)
    name = db.Column(db.String(120), nullable=False)
    mode = db.Column(db.String(20), nullable=False, default="SANDBOX")
    status = db.Column(db.String(40), nullable=False, default="SANDBOX")
    adapter_version = db.Column(db.String(20), nullable=False, default="v1")
    source_of_truth = db.Column(db.String(120), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
    transactions = db.relationship("IntegrationTransaction", back_populates="connection", lazy=True)


class IntegrationTransaction(db.Model):
    __tablename__ = "integration_transactions"
    __table_args__ = (
        db.UniqueConstraint("idempotency_key", name="uq_integration_idempotency_key"),
        db.Index("ix_integration_target_created", "target_system", "created_at"),
        db.Index("ix_integration_status_created", "status", "created_at"),
    )
    id = db.Column(db.Integer, primary_key=True)
    transaction_id = db.Column(db.String(40), unique=True, nullable=False)
    correlation_id = db.Column(db.String(120), nullable=False, index=True)
    idempotency_key = db.Column(db.String(200), nullable=False)
    case_id = db.Column(db.String(120), nullable=True, index=True)
    connection_id = db.Column(db.Integer, db.ForeignKey("integration_connections.id"), nullable=False)
    source_system = db.Column(db.String(50), nullable=False)
    target_system = db.Column(db.String(50), nullable=False)
    operation = db.Column(db.String(80), nullable=False)
    status = db.Column(db.String(30), nullable=False)
    request_payload = db.Column(db.Text, nullable=False)
    response_payload = db.Column(db.Text, nullable=True)
    request_hash = db.Column(db.String(64), nullable=False)
    response_hash = db.Column(db.String(64), nullable=True)
    error_code = db.Column(db.String(40), nullable=True)
    error_message = db.Column(db.Text, nullable=True)
    attempt_count = db.Column(db.Integer, nullable=False, default=1)
    actor_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
    connection = db.relationship("IntegrationConnection", back_populates="transactions")
    actor = db.relationship("User")


class SecurityEvent(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    severity = db.Column(db.String(30), default="Medium")
    module = db.Column(db.String(120), nullable=False)
    description = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(50), default="Open")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class Document(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    document_type = db.Column(db.String(80), default="General")
    link_type = db.Column(db.String(80), nullable=True)
    link_id = db.Column(db.Integer, nullable=True)
    uploaded_by = db.Column(db.String(120), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    title = db.Column(db.String(200), nullable=False)
    message = db.Column(db.Text, nullable=False)
    is_read = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class BackupRecord(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    backup_name = db.Column(db.String(200), nullable=False)
    storage_path = db.Column(db.String(255), nullable=True)
    status = db.Column(db.String(50), default="Completed")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class ApprovalRecord(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    entity_type = db.Column(db.String(80), nullable=False)
    entity_id = db.Column(db.Integer, nullable=False)
    approver = db.Column(db.String(200), nullable=False)
    status = db.Column(db.String(50), default="Pending")
    comments = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class Policy(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    category = db.Column(db.String(120), nullable=False)
    version = db.Column(db.String(50), nullable=True)
    owner = db.Column(db.String(200), nullable=True)
    status = db.Column(db.String(50), default="Draft")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class ArchiveRecord(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    archive_type = db.Column(db.String(120), nullable=False)
    storage_path = db.Column(db.String(255), nullable=True)
    status = db.Column(db.String(50), default="Archived")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class PerformanceIndicator(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    category = db.Column(db.String(120), nullable=False)
    target = db.Column(db.String(80), nullable=True)
    actual = db.Column(db.String(80), nullable=True)
    status = db.Column(db.String(50), default="On Track")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class ComplianceCheck(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    category = db.Column(db.String(120), nullable=False)
    owner = db.Column(db.String(200), nullable=True)
    status = db.Column(db.String(50), default="Monitoring")
    notes = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class BudgetForecast(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    fiscal_year = db.Column(db.String(20), nullable=False)
    department = db.Column(db.String(200), nullable=False)
    allocation = db.Column(db.Float, default=0.0)
    expenditure = db.Column(db.Float, default=0.0)
    variance = db.Column(db.Float, default=0.0)
    status = db.Column(db.String(50), default="On Track")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class PortfolioProject(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    project_name = db.Column(db.String(200), nullable=False)
    phase = db.Column(db.String(120), nullable=False)
    owner = db.Column(db.String(200), nullable=True)
    due_date = db.Column(db.String(50), nullable=True)
    completion_percent = db.Column(db.Integer, default=0)
    status = db.Column(db.String(50), default="Planned")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class StrategicPlan(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    objective = db.Column(db.String(200), nullable=False)
    outcome = db.Column(db.String(200), nullable=False)
    owner = db.Column(db.String(200), nullable=True)
    target_date = db.Column(db.String(50), nullable=True)
    status = db.Column(db.String(50), default="Planned")
    progress_percent = db.Column(db.Integer, default=0)
    notes = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class Stakeholder(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    organisation = db.Column(db.String(200), nullable=True)
    role = db.Column(db.String(200), nullable=True)
    influence = db.Column(db.String(50), default="Medium")
    engagement_status = db.Column(db.String(50), default="Active")
    notes = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class TrainingRecord(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    category = db.Column(db.String(120), nullable=False)
    provider = db.Column(db.String(200), nullable=True)
    target_group = db.Column(db.String(200), nullable=True)
    completion_date = db.Column(db.String(50), nullable=True)
    status = db.Column(db.String(50), default="Scheduled")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class Beneficiary(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    beneficiary_name = db.Column(db.String(200), nullable=False)
    program = db.Column(db.String(200), nullable=False)
    location = db.Column(db.String(200), nullable=True)
    priority = db.Column(db.String(50), default="Medium")
    status = db.Column(db.String(50), default="Active")
    notes = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class ServiceFeedback(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    service_name = db.Column(db.String(200), nullable=False)
    beneficiary_name = db.Column(db.String(200), nullable=False)
    rating = db.Column(db.Integer, nullable=True)
    comment = db.Column(db.Text, nullable=True)
    status = db.Column(db.String(50), default="Open")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
