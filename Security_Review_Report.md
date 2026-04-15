# Comprehensive White-Box Security Code Review Report

## Executive Summary
A comprehensive static code analysis and security review of the ZR.Admin.NET Web API application was conducted against the OWASP Web Security Testing Guide (WSTG) and OWASP Top 10. The application exhibits several strong security practices, including the implementation of JWT-based authentication, RBAC via custom permission filters (`[ActionPermissionFilter]`), and proactive PII masking.

However, there are critical vulnerabilities identified regarding unauthorized data access, specifically through the dictionary data endpoints which allow unauthenticated execution of custom SQL queries defined in the database. Furthermore, several endpoints meant for system configuration and administrative functionality are mistakenly exposed to unauthenticated users via the `[AllowAnonymous]` attribute, leading to severe information disclosure risks.

**Overall Risk Rating: High**

## Findings Summary Table

| ID | Category | Severity | Location | Priority |
|---|---|---|---|---|
| VULN-001 | WSTG-ATHZ-02 / A01:2021 – Broken Access Control | Critical | `SysDictDataController.cs:GetDicts()` | 1 |
| VULN-002 | WSTG-INFO-02 / A01:2021 – Broken Access Control | High | `SysConfigController.cs:GetConfigKey()` | 2 |
| VULN-003 | WSTG-ATHN-04 / A04:2021 – Insecure Design | Medium | `CommonController.cs:InitSeedData()`, `UpdateSeedData()` | 3 |
| VULN-004 | WSTG-INPV-14 / A03:2021 – Injection | Medium | `GlobalActionMonitor.cs:OnResultExecuted()` | 4 |

---

## Detailed Findings

### VULN-001: Unauthenticated Execution of Custom Dictionary SQL Queries
**Category:** WSTG-ATHZ-02 (Bypass Authorization Schema) + A01:2021 – Broken Access Control
**Severity:** Critical
**Description:** The application features a dynamic dictionary system where dictionaries starting with `sql_` or `cus_` execute custom SQL queries stored in the database (`SysDictType.CustomSql`). The endpoints `/types` and `/dicts` in `SysDictDataController` are marked with `[AllowAnonymous]`, allowing unauthenticated users to request these dictionary types. While the SQL itself is not directly user-provided, an attacker can enumerate and execute any pre-configured custom SQL queries, potentially leaking sensitive data from arbitrary database tables if such a dictionary type exists.
**Location:**
- `ZR.Admin.WebApi/Controllers/System/SysDictDataController.cs` in `DictTypes()` and `GetDictTypes()` endpoints, leading to `GetDicts(string[] dicts)`.
- `ZR.ServiceCore/Services/SysDictService.cs` in `SelectDictDataByCustomSql()`.
**Evidence:**
```csharp
[AllowAnonymous]
[HttpPost("dicts")]
public async Task<IActionResult> GetDictTypes()
{
    var data = await HttpContext.GetBodyAsync();
    return SUCCESS(GetDicts(JsonConvert.DeserializeObject<string[]>(data)));
}

private List<SysdictDataParamDto> GetDicts([FromBody]string[] dicts)
{
    // ...
        if (dic.StartsWith("cus_") || dic.StartsWith("sql_"))
        {
            vo.List.AddRange(SysDictService.SelectDictDataByCustomSql(dic));
        }
    // ...
}
```
**Potential Impact:** An unauthenticated attacker can execute any pre-defined custom SQL queries on the server. If administrators have created custom dictionaries that query sensitive tables (e.g., users, orders), this data can be fully extracted by any external attacker.
**Remediation:** Remove the `[AllowAnonymous]` attribute from endpoints that retrieve custom SQL dictionary data. If unauthenticated access to *certain* static dictionaries is required for the frontend, split the logic: allow public access only to a whitelist of safe, static dictionaries, and strictly require authentication (and potentially administrative authorization) for any dictionary prefixed with `sql_` or `cus_`.

---

### VULN-002: Unauthenticated Access to System Configuration Values
**Category:** WSTG-INFO-02 (Review Webserver Metafiles for Information Leakage) + A01:2021 – Broken Access Control
**Severity:** High
**Description:** The `GetConfigKey` endpoint in `SysConfigController` is marked with `[AllowAnonymous]`. This endpoint allows any user to query the value of any system configuration key stored in the database.
**Location:** `ZR.Admin.WebApi/Controllers/System/SysConfigController.cs`, `GetConfigKey()` method.
**Evidence:**
```csharp
[HttpGet("configKey/{configKey}")]
[AllowAnonymous]
public IActionResult GetConfigKey(string configKey)
{
    var response = _SysConfigService.Queryable().First(f => f.ConfigKey == configKey);
    return SUCCESS(response?.ConfigValue);
}
```
**Potential Impact:** System configurations often contain sensitive information such as third-party API keys, internal network paths, or feature flags. An attacker can enumerate or guess `configKey` names (e.g., `sys.account.register`, which is seen in the codebase) and extract their values, facilitating further attacks.
**Remediation:** Remove the `[AllowAnonymous]` attribute from `GetConfigKey`. If the frontend requires specific configuration keys before login (like the captcha toggle), create a dedicated, hardcoded endpoint that only returns non-sensitive, explicitly allowed configuration keys.

---

### VULN-003: Insecure Exposure of Seed Data Initialization Endpoints
**Category:** WSTG-ATHN-04 (Bypass Authentication Schema) + A04:2021 – Insecure Design
**Severity:** Medium
**Description:** The `InitSeedData` and `UpdateSeedData` endpoints in `CommonController` are protected by `[AllowAnonymous]` and `WebHostEnvironment.IsDevelopment()`. While the environment check provides some protection, `[AllowAnonymous]` means that if the application is ever deployed to a staging or internet-facing environment with the environment variable mistakenly set to "Development", any unauthenticated user can trigger a database re-initialization, potentially destroying data or resetting administrative credentials.
**Location:** `ZR.Admin.WebApi/Controllers/CommonController.cs`, `InitSeedData()` and `UpdateSeedData()` methods.
**Evidence:**
```csharp
[HttpGet]
[AllowAnonymous]
[ActionPermissionFilter(Permission = "common")]
[Log(BusinessType = BusinessType.INSERT, Title = "初始化数据")]
public IActionResult InitSeedData(bool clean = false)
{
    if (!WebHostEnvironment.IsDevelopment())
    {
        return ToResponse(ResultCode.CUSTOM_ERROR, "导入数据失败，请在开发模式下初始化");
    }
    // ... initializes DB, potentially cleaning data ...
}
```
**Potential Impact:** If the "Development" environment is exposed, attackers can wipe out the database or reset it to default states, leading to severe denial of service and loss of data integrity.
**Remediation:** Remove `[AllowAnonymous]`. Require strict administrative privileges (`[ActionPermissionFilter]`) to execute these endpoints, even in development environments, or remove these endpoints entirely from the compiled release builds using preprocessor directives (`#if DEBUG`).

---

### VULN-004: Potential Log Injection / Improper Input Validation in Global Action Monitor
**Category:** WSTG-INPV-14 (Testing for Log Injection) + A03:2021 – Injection
**Severity:** Low / Informational
**Description:** The `GlobalActionMonitor` filter logs all request parameters (`context.HttpContext.GetRequestValue(...)`). If an attacker sends a malicious payload containing newline characters or crafted JSON within the request body/parameters, it may break log parsing systems or allow the attacker to forge log entries (Log Forging).
**Location:** `ZR.ServiceCore/Filters/GlobalActionMonitor.cs`, `OnResultExecuted()` method.
**Evidence:**
```csharp
SysOperLog sysOperLog = new()
{
    // ...
    OperParam = HttpContextExtension.GetRequestValue(context.HttpContext, method)
};
```
**Potential Impact:** Attackers can inject fake log entries, making incident response and auditing difficult. If logs are rendered in an admin dashboard without proper output encoding, this could also lead to Stored XSS.
**Remediation:** Ensure that `GetRequestValue` sanitizes input by escaping newline characters (`\n`, `\r`) before storing them. Verify that the administrative frontend (Vue) properly encodes this data when displaying the operation logs to prevent XSS.

---

## Positive Observations
1. **Strong Authentication Middleware:** The application correctly uses `JwtAuthMiddleware` to enforce authentication globally by default, shifting to a whitelist approach for `[AllowAnonymous]`.
2. **PII Masking:** The `SysUserService` correctly implements data masking for sensitive fields like `Phonenumber` and `Email` based on the user's specific permissions (`HttpContextExtension.HasSensitivePerm`).
3. **Password Security:** The user password field in the `SysUser` model uses `[JsonIgnore]`, ensuring it is never accidentally serialized and leaked in API responses.
4. **Rate Limiting & Security Filters:** The application incorporates IP Rate Limiting (`AspNetCoreRateLimit`) and global exception handling, mitigating basic DoS attempts and preventing stack traces from leaking to the client.

## General Recommendations
1. **Review all `[AllowAnonymous]` attributes:** Conduct a strict review of all endpoints marked with `[AllowAnonymous]`. Ensure that no business logic or database queries that return variable data are exposed without authentication unless absolutely necessary for public frontend consumption.
2. **Separate Public vs. Admin APIs:** Consider splitting the API into two distinct projects or routing namespaces (e.g., `/api/admin` and `/api/public`). The admin API should never use `[AllowAnonymous]`, completely eliminating the risk of accidental exposure.
3. **Audit Custom SQL Execution:** Storing executable SQL in the database (`sys_dict_type`) is an anti-pattern that inherently carries high risk. Transition these dynamic dictionary queries to strongly-typed ORM queries or stored procedures where the parameters and tables are strictly validated and controlled by the application code, not the database row.

## No Issues Detected
- **Cryptography & Secrets Management:** Secrets (JWT keys, App IDs) are properly managed via `appsettings.json` and Options binding. No hardcoded credentials or weak cryptographic algorithms were observed in the token generation logic (`JwtUtil.cs`).
