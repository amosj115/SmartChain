from datetime import datetime

from .extensions import db
from .models import (
    AnnualProcurementPlan,
    Asset,
    AuditLog,
    BackupRecord,
    Contract,
    Department,
    DemandRequest,
    Directorate,
    Document,
    Employee,
    InternalControl,
    Notification,
    PasswordPolicy,
    Permission,
    ProcurementRequest,
    Requisition,
    RiskRegister,
    Role,
    SecurityEvent,
    Supplier,
    Tender,
    TenderBidder,
    TenderCriterion,
    TenderCriterionConfig,
    TenderEvaluatorAssignment,
    TenderProfile,
    TenderScreeningRequirement,
    TenderStageEvent,
    TenderSubcriterion,
    TripRequest,
    TravelRequest,
    Unit,
    User,
)


def create_roles_and_permissions():
    role_map = {
        "System Administrator": [
            "manage_users",
            "manage_roles",
            "manage_security",
            "view_audit",
            "manage_app",
            "integration.view",
            "integration.manage",
            "integration.test",
            "integration.retry",
            "integration.reconcile",
            "integration.configure",
            "integration.audit",
        ],
        "Security Administrator": ["manage_security", "view_audit", "review_security_events"],
        "DSD Executive / Executive Management": ["view_dashboard", "view_reports", "approve_budget"],
        "CFO / Finance Authority": ["view_finance", "approve_budget", "approve_procurement"],
        "SCM Manager": ["manage_demand", "manage_procurement", "approve_requisition", "integration.view"],
        "SCM Officer / Practitioner": ["create_requisition", "manage_supplier", "manage_procurement"],
        "SCM Intake Officer": ["manage_procurement", "review_requisition"],
        "SCM Clerk": ["manage_procurement", "review_requisition"],
        "SCM Supervisor": ["manage_procurement", "approve_requisition"],
        "Transport Manager": ["manage_transport", "approve_trip"],
        "Transport Officer": ["manage_transport", "process_trip"],
        "Transport Supervisor": ["manage_transport", "approve_trip", "assign_transport"],
        "Fleet Administrator": ["manage_transport", "manage_fleet", "manage_compliance"],
        "Directorate DD": ["submit_directorate_transport", "authorise_directorate_transport"],
        "Directorate Director": ["submit_directorate_transport", "authorise_directorate_transport"],
        "Directorate Chief Director": ["submit_directorate_transport", "authorise_directorate_transport"],
        "Asset Manager": ["manage_assets"],
        "Contract Manager": ["manage_contracts"],
        "Internal Control Officer": ["manage_controls", "review_compliance"],
        "Internal Audit": ["view_audit", "review_controls", "integration.view", "integration.audit"],
        "Risk Officer": ["manage_risk"],
        "BEC Member": ["review_tender"],
        "BAC Member": ["review_bac"],
        "Employee": ["submit_requisition", "view_dashboard"],
        "Read-Only / Management Viewer": ["view_dashboard", "view_reports"],
    }

    for role_name, perm_names in role_map.items():
        role = Role.query.filter_by(name=role_name).first()
        if not role:
            role = Role(name=role_name, description=f"{role_name} role")
            db.session.add(role)
            db.session.flush()
        for perm_name in perm_names:
            if not Permission.query.filter_by(name=perm_name, role_id=role.id).first():
                db.session.add(Permission(name=perm_name, role=role))
    db.session.commit()


def seed_demo_data(app):
    if not Department.query.first():
        create_roles_and_permissions()
        dept = Department(name="National Department of Social Development", code="DSD", description="National Office")
        db.session.add(dept)
        db.session.flush()

        directorate = Directorate(name="Corporate Services", code="CORP", department_id=dept.id)
        db.session.add(directorate)
        db.session.flush()

        unit = Unit(name="Supply Chain Management Unit", code="SCM", directorate_id=directorate.id)
        db.session.add(unit)
        db.session.flush()

        admin_role = Role.query.filter_by(name="System Administrator").first()
        scm_role = Role.query.filter_by(name="SCM Manager").first()
        employee_role = Role.query.filter_by(name="Employee").first()

        admin_emp = Employee(
            employee_number="DSD001",
            first_name="Development",
            last_name="Administrator",
            title="Director",
            position="System Administrator",
            email="admin@smartchain.test",
            phone="0000000000",
            department_id=dept.id,
            directorate_id=directorate.id,
            unit_id=unit.id,
            role_id=admin_role.id,
            account_status="active",
        )
        db.session.add(admin_emp)
        db.session.flush()

        admin_user = User(
            username="devadmin",
            email="devadmin@smartchain.test",
            full_name="Development Administrator",
            role_id=admin_role.id,
            employee_id=admin_emp.id,
            is_active=True,
        )
        db.session.add(admin_user)
        db.session.flush()

        manager_emp = Employee(
            employee_number="DSD002",
            first_name="Procurement",
            last_name="Manager",
            title="Manager",
            position="SCM Manager",
            email="manager@smartchain.test",
            phone="1111111111",
            department_id=dept.id,
            directorate_id=directorate.id,
            unit_id=unit.id,
            role_id=scm_role.id,
            account_status="active",
        )
        db.session.add(manager_emp)
        db.session.flush()

        user = User(
            username="manager",
            email="manager@smartchain.test",
            full_name="Procurement Manager",
            role_id=scm_role.id,
            employee_id=manager_emp.id,
            is_active=True,
        )
        db.session.add(user)

        staff_emp = Employee(
            employee_number="DSD003",
            first_name="Sample",
            last_name="Employee",
            title="Officer",
            position="SCM Officer",
            email="employee@smartchain.test",
            phone="2222222222",
            department_id=dept.id,
            directorate_id=directorate.id,
            unit_id=unit.id,
            role_id=employee_role.id,
            account_status="active",
        )
        db.session.add(staff_emp)
        db.session.flush()

        staff_user = User(
            username="employee",
            email="employee@smartchain.test",
            full_name="Sample Employee",
            role_id=employee_role.id,
            employee_id=staff_emp.id,
            is_active=True,
        )
        db.session.add(staff_user)
        db.session.flush()

        if not app.config.get("TESTING"):
            db.session.add_all(
                [
                    DemandRequest(
                        title="Fleet replacement demand",
                        description="Replacement of aging fleet units for delivery service.",
                        responsible_unit="SCM Unit",
                        estimated_cost=350000.0,
                        priority="High",
                        timing="Q4",
                        status="Approved",
                        justification="Operational continuity and service reliability.",
                    ),
                    AnnualProcurementPlan(
                        item_name="IT Infrastructure Upgrade",
                        estimated_value=875000.0,
                        procurement_method="Open Tender",
                        responsible_unit="Corporate Services",
                        planned_date="2026-10-15",
                        budget_allocation=900000.0,
                        status="Planned",
                    ),
                    Requisition(
                        requisition_number="RQ-1001",
                        requester="Sample Employee",
                        department="National Department of Social Development",
                        directorate="Corporate Services",
                        unit="Supply Chain Management Unit",
                        description="Laptop refresh for three officers",
                        motivation="Support productivity and approved staff digital requirements.",
                        estimated_value=26000.0,
                        budget="Approved Budget 2026/27",
                        priority="Medium",
                        status="Approved",
                    ),
                    ProcurementRequest(
                        title="Laptop refresh",
                        procurement_method="Request for Quotations",
                        estimated_value=30000.0,
                        status="Approved",
                        recommendation="Proceed with compliant supplier comparison.",
                    ),
                    Supplier(
                        name="DemoTech Trading",
                        registration_number="REG-001",
                        service_categories="IT Equipment, Accessories",
                        status="Active",
                        contact_email="sales@demotech.test",
                        phone="5551111",
                    ),
                    Tender(
                        tender_number="TND-001",
                        title="ICT Equipment Supply",
                        description="Supply of laptops and accessories",
                        estimated_value=500000.0,
                        closing_date="2026-09-30",
                        status="Open",
                    ),
                    Contract(
                        contract_number="CON-001",
                        supplier="DemoTech Trading",
                        tender="TND-001",
                        start_date="2026-10-01",
                        end_date="2027-09-30",
                        value=500000.0,
                        status="Active",
                    ),
                    TripRequest(
                        title="Provincial site visit",
                        origin="Pretoria",
                        destination="Polokwane",
                        purpose="Monitoring and oversight",
                        status="Approved",
                    ),
                    TravelRequest(
                        title="Official travel to Cape Town",
                        purpose="Stakeholder engagements and training",
                        destination="Cape Town",
                        status="Approved",
                    ),
                    Asset(
                        asset_number="AST-001",
                        description="Dell Laptop",
                        category="IT Equipment",
                        location="Head Office",
                        value=18000.0,
                        condition="Good",
                        status="Active",
                    ),
                    InternalControl(
                        control_objective="Procurement compliance approval",
                        process_name="Procurement",
                        risk_rating="Medium",
                        status="Active",
                    ),
                    RiskRegister(
                        title="Supplier concentration risk",
                        category="Procurement",
                        likelihood="Medium",
                        impact="High",
                        risk_rating="High",
                        status="Open",
                    ),
                    Document(title="Supplier registration pack", document_type="Supplier", link_type="supplier", link_id=1, uploaded_by="admin"),
                    Notification(user_id=admin_user.id, title="Approval pending", message="A requisition is ready for review."),
                    Notification(user_id=staff_user.id, title="Welcome", message="Welcome to SmartChain."),
                    SecurityEvent(severity="Medium", module="Auth", description="Successful development access was recorded.", status="Resolved"),
                    AuditLog(module="Auth", action="login", entity="user", details="Development administrator accessed the system.", user_id=admin_user.id),
                    BackupRecord(backup_name="nightly-smartchain-db", storage_path="./backups", status="Completed"),
                ]
            )

        db.session.commit()

    elif not Role.query.first():
        create_roles_and_permissions()

    create_roles_and_permissions()
    if app.config.get("ENV") == "development":
        ensure_test_admin()
    if not app.config.get("TESTING"):
        ensure_demo_directorate_authority()
        ensure_demo_tender()


def ensure_test_admin():
    role = Role.query.filter_by(name="System Administrator").first()
    if not role:
        create_roles_and_permissions()
        role = Role.query.filter_by(name="System Administrator").first()
    user = User.query.filter_by(username="smartchain.admin").first()
    if not user:
        user = User(username="smartchain.admin", email="smartchain.admin@smartchain.test", full_name="SmartChain Test Administrator", role_id=role.id, is_active=True)
        db.session.add(user)
        db.session.flush()
    policy = PasswordPolicy.query.filter_by(user_id=user.id).first()
    if not policy:
        db.session.add(PasswordPolicy(user_id=user.id, must_change_password=False))
    else:
        policy.must_change_password = False
    db.session.commit()


def ensure_demo_directorate_authority():
    role = Role.query.filter_by(name="Directorate Director").first()
    department = Department.query.first()
    directorate = Directorate.query.first()
    unit = Unit.query.first()
    if not role or not department or not directorate or not unit:
        return
    user = User.query.filter_by(username="directorate.director").first()
    if user:
        return
    employee = Employee(
        employee_number="DSD004",
        first_name="Directorate",
        last_name="Director",
        title="Director",
        position="Directorate Director",
        email="directorate.director@smartchain.test",
        phone="0000000004",
        department_id=department.id,
        directorate_id=directorate.id,
        unit_id=unit.id,
        role_id=role.id,
        account_status="active",
    )
    db.session.add(employee)
    db.session.flush()
    db.session.add(User(
        username="directorate.director",
        email="directorate.director@smartchain.test",
        full_name="Directorate Director",
        role_id=role.id,
        employee_id=employee.id,
        is_active=True,
    ))
    db.session.commit()


def create_demo_user(username, password, full_name, role_name):
    role = Role.query.filter_by(name=role_name).first()
    if not role:
        create_roles_and_permissions()
        role = Role.query.filter_by(name=role_name).first()
    user = User.query.filter_by(username=username).first()
    if not user:
        user = User(username=username, email=f"{username}@smartchain.test", full_name=full_name, role_id=role.id)
        db.session.add(user)
        db.session.commit()
    return user


def disable_all_passwords():
    User.query.update({User.password_hash: None})
    PasswordPolicy.query.update({PasswordPolicy.must_change_password: False})
    db.session.commit()


def ensure_demo_tender():
    tender = Tender.query.filter_by(tender_number="TECH-2026-001").first()
    if tender:
        return

    tender = Tender(
        tender_number="TECH-2026-001",
        title="Technology Services Tender 2026",
        description="Technology services for the National Department of Social Development.",
        estimated_value=2500000.0,
        closing_date="2026-10-30",
        status="Open",
        profile=TenderProfile(
            directorate="Corporate Services",
            responsible_official="SCM Tender Administrator",
            procurement_category="Information and Communication Technology",
            procurement_type="Services",
            opening_date="2026-09-01",
            evaluation_methodology="Functionality and price with tender-specific weighted criteria",
            mandatory_requirements="Signed declaration; tax compliance; technical response",
            functionality_required=True,
            price_preference_method="Applicable preference points recorded during authorised comparative review",
            minimum_functionality_threshold=60.0,
        ),
    )
    db.session.add(tender)
    db.session.flush()

    for index in range(1, 21):
        db.session.add(TenderBidder(
            tender=tender,
            legal_name=f"Technology Company {index:02d}",
            supplier_reference=f"TECH-REF-{index:03d}",
            bid_price=100000.0 + index * 10000,
            compliance_status="Pending",
            evaluation_status="Not Started",
        ))

    criteria_data = [
        ("Technical capability", "Functionality", 30, 30, "points", "Technical team and infrastructure evidence"),
        ("Methodology and implementation", "Functionality", 25, 25, "percentage", "Implementation plan and delivery approach"),
        ("Service support model", "Functionality", 20, 20, "1-5", "Support, continuity and service levels"),
        ("Transformation and local impact", "Functionality", 15, 15, "1-10", "Transformation and skills development response"),
        ("Price and preference", "Price", 10, 10, "custom", "Authorised price and preference assessment"),
    ]
    for position, (name, category, weight, max_score, framework, evidence) in enumerate(criteria_data):
        criterion = TenderCriterion(
            tender=tender,
            name=name,
            description=f"Tender-specific {category.lower()} evaluation criterion.",
            weight=weight,
            max_score=max_score,
            scoring_framework=framework,
            instructions=f"Evaluate {name.lower()} against the approved tender methodology.",
        )
        criterion.config = TenderCriterionConfig(
            category=category,
            minimum_qualifying_score=None,
            mandatory=category == "Functionality",
            evidence_required=evidence,
            position=position,
        )
        db.session.add(criterion)
        if position == 0:
            db.session.flush()
            for child_position, (child_name, points) in enumerate([
                ("Technical team", 10),
                ("Infrastructure", 5),
                ("Methodology", 10),
                ("Support model", 5),
            ]):
                db.session.add(TenderSubcriterion(
                    criterion=criterion,
                    name=child_name,
                    description=f"Evidence for {child_name.lower()}.",
                    max_points=points,
                    position=child_position,
                ))

    for position, (name, category) in enumerate([
        ("Bid submitted before closing date", "Eligibility"),
        ("Mandatory forms and declarations present", "Mandatory documentation"),
        ("Technical response included", "Technical compliance"),
    ]):
        db.session.add(TenderScreeningRequirement(
            tender=tender,
            name=name,
            category=category,
            mandatory=True,
            position=position,
        ))

    evaluator_role = Role.query.filter_by(name="BEC Member").first()
    if evaluator_role:
        for index in range(1, 6):
            evaluator = User.query.filter_by(username=f"tender.evaluator.{index}").first()
            if not evaluator:
                evaluator = User(
                    username=f"tender.evaluator.{index}",
                    email=f"tender.evaluator.{index}@smartchain.test",
                    full_name=f"Tender Evaluator {index}",
                    role_id=evaluator_role.id,
                    is_active=True,
                )
                db.session.add(evaluator)
                db.session.flush()
            db.session.add(TenderEvaluatorAssignment(tender=tender, user=evaluator, assigned_by_id=User.query.filter_by(username="devadmin").first().id))

    db.session.add(TenderStageEvent(
        tender=tender,
        stage="PLANNING",
        status="Created",
        details="Operational demonstration tender seeded for the Tender Command Workspace.",
        user_id=User.query.filter_by(username="devadmin").first().id,
    ))
    db.session.commit()
