import frappe

COMPANY_ADMINISTRATOR_PROFILE = "Company Administrator"
PLATFORM_ADMIN_DOCTYPE = "Multi Tenancy Administrator"


def get_user_tenant(user=None):
    user = user or frappe.session.user

    return frappe.db.get_value(
        "Tenant User",
        {"user": user, "status": "Active"},
        "tenant",
        order_by="modified desc",
    )


def is_platform_admin(user=None):
    """
    Platform administrators are System Managers or users registered
    in the Multi Tenancy Administrator DocType.
    """

    user = user or frappe.session.user

    if user == "Administrator":
        return True

    if "System Manager" in frappe.get_roles(user):
        return True

    return bool(
        frappe.db.exists(
            PLATFORM_ADMIN_DOCTYPE,
            {"user": user, "status": "Active"},
        )
    )


def is_company_administrator(user):
    """Check the user's Role Profile rather than a Role."""

    return frappe.db.get_value(
        "User",
        user,
        "role_profile_name",
    ) == COMPANY_ADMINISTRATOR_PROFILE


def _tenant_scoped_query(user, table):
    """Build a permission query condition restricting rows to the user's tenant."""

    if is_platform_admin(user):
        return ""

    tenant = get_user_tenant(user)

    if not tenant:
        return "1=0"

    return "`{0}`.`tenant` = {1}".format(
        table,
        frappe.db.escape(tenant),
    )


def _make_query(table):
    def query(user=None):
        return _tenant_scoped_query(user or frappe.session.user, table)

    query.__name__ = "{0}_query".format(table.lower().replace(" ", "_"))
    return query


# DocType specific permission query functions for multi-tenancy scoping
def item_query(user=None):
    return _tenant_scoped_query(user or frappe.session.user, "tabItem")


def item_group_query(user=None):
    return _tenant_scoped_query(user or frappe.session.user, "tabItem Group")


def customer_query(user=None):
    return _tenant_scoped_query(user or frappe.session.user, "tabCustomer")


def supplier_query(user=None):
    return _tenant_scoped_query(user or frappe.session.user, "tabSupplier")


def brand_query(user=None):
    return _tenant_scoped_query(user or frappe.session.user, "tabBrand")


def price_list_query(user=None):
    return _tenant_scoped_query(user or frappe.session.user, "tabPrice List")


def item_price_query(user=None):
    return _tenant_scoped_query(user or frappe.session.user, "tabItem Price")


customer_group_query = _make_query("tabCustomer Group")
supplier_group_query = _make_query("tabSupplier Group")
territory_query = _make_query("tabTerritory")
pricing_rule_query = _make_query("tabPricing Rule")
holiday_list_query = _make_query("tabHoliday List")
department_query = _make_query("tabDepartment")
designation_query = _make_query("tabDesignation")
branch_query = _make_query("tabBranch")
letter_head_query = _make_query("tabLetter Head")


def user_query(user):
    """
    Restricts the User list view so that:
    - Global Administrators and System Managers see all users.
    - Company Administrators and standard users only see users
      belonging to their assigned tenant/company.
    """
    user = user or frappe.session.user

    # Bypass restriction for global tech/system admins
    if is_platform_admin(user):
        return ""  # Sees all users site-wide

    # Find the tenant linked to this user
    tenant = frappe.db.get_value(
        "Tenant User",
        {"user": user, "status": "Active"},
        "tenant",
        order_by="modified desc",
    )

    if not tenant:
        return "1=0"  # No tenant assigned, sees nothing

    # Find all user IDs linked to this same tenant
    tenant_users = frappe.get_all(
        "Tenant User",
        filters={"tenant": tenant, "status": "Active"},
        pluck="user",
    )

    if not tenant_users:
        return "1=0"

    escaped_users = ", ".join([frappe.db.escape(u) for u in tenant_users])

    # Restrict User list to only users within the same tenant
    return "`tabUser`.`name` IN ({0})".format(escaped_users)


# Doc level permission check for multi-tenancy scoping
def tenant_has_permission(doc, user=None, permission_type=None):
    user = user or frappe.session.user

    if is_platform_admin(user):
        return True

    tenant = get_user_tenant(user)

    if not tenant:
        return False

    if doc.get("tenant") != tenant:
        return False

    return True


# Doc level permission check for User doctype
def user_has_permission(doc, ptype="read", user=None):
    user = user or frappe.session.user

    # Global admins have full access
    if is_platform_admin(user):
        return True

    # Users can always view/edit their own profile
    if doc.name == user:
        return True

    # Get target user's tenant vs current user's tenant
    target_tenant = frappe.db.get_value(
        "Tenant User",
        {"user": doc.name, "status": "Active"},
        "tenant",
        order_by="modified desc",
    )
    current_tenant = get_user_tenant(user)

    # Allow access if both belong to the same tenant and the user
    # holds the Company Administrator Role Profile.
    if (
        current_tenant
        and target_tenant == current_tenant
        and is_company_administrator(user)
    ):
        return True

    return False


# DocTypes that carry tenant/company scoping fields.
SCOPED_DOCTYPES = [
    "Item",
    "Item Group",
    "Brand",
    "Customer",
    "Customer Group",
    "Supplier",
    "Supplier Group",
    "Territory",
    "Price List",
    "Item Price",
    "Pricing Rule",
    "Holiday List",
    "Department",
    "Designation",
    "Branch",
    "Letter Head",
]


def assign_tenant_context(doc, method=None):
    """
    Default the tenant (and company) on newly saved scoped records
    from the session user's Tenant User registration.
    """

    if not doc.meta.has_field("tenant") or doc.get("tenant"):
        return

    if is_platform_admin():
        return

    tenant = get_user_tenant()

    if not tenant:
        return

    doc.tenant = tenant

    if doc.meta.has_field("company") and not doc.get("company"):
        company = frappe.db.get_value("Tenant", tenant, "company")

        if company:
            doc.company = company


def _user_company(user):
    """Resolve a User's Company from User Permissions or user defaults."""

    companies = frappe.get_all(
        "User Permission",
        filters={"user": user, "allow": "Company"},
        pluck="for_value",
    )

    companies = {
        company
        for company in companies
        if company and frappe.db.exists("Company", company)
    }

    if len(companies) == 1:
        return companies.pop()

    if len(companies) > 1:
        return None

    default_company = frappe.defaults.get_user_default("company", user)

    if default_company and frappe.db.exists("Company", default_company):
        return default_company

    return None


def sync_tenant_user(doc, method=None):
    """
    Keep Tenant User registrations in sync when a User is saved,
    so tenant users can see/manage users of their own tenant.
    """

    if doc.name in ("Administrator", "Guest"):
        return

    company = _user_company(doc.name)

    if not company:
        return

    tenant = frappe.db.get_value(
        "Tenant",
        {"company": company},
        "name",
    )

    if not tenant:
        return

    existing = frappe.db.get_value(
        "Tenant User",
        {"user": doc.name},
        "name",
        order_by="modified desc",
    )

    if existing:
        record = frappe.get_doc("Tenant User", existing)
    else:
        record = frappe.new_doc("Tenant User")
        record.user = doc.name

    record.tenant = tenant
    record.status = "Active" if doc.enabled else "Disabled"

    if record.is_new():
        record.insert(ignore_permissions=True)
    else:
        record.save(ignore_permissions=True)
