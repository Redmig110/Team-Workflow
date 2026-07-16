"use strict";

const STEP_DEFINITIONS = [
  ["old_login", "旧号登录"],
  ["new_login", "新号注册"],
  ["invite", "邀请新号"],
  ["old_leave", "旧号退出"],
  ["pat", "创建令牌"],
  ["cpa", "生成 CPA"],
  ["push", "推送管理端"],
  ["push_sub2api", "推送 Sub2API"],
];

const STEP_LABELS = Object.fromEntries(STEP_DEFINITIONS);
const STEP_STATE_LABELS = {
  pending: "待执行",
  queued: "待执行",
  active: "执行中",
  running: "执行中",
  done: "完成",
  succeeded: "完成",
  skipped: "跳过",
  cancelled: "已停止",
  error: "失败",
  failed: "失败",
};

const WORKSPACE_STATUS = {
  needs_account: ["待分配", "warning"],
  ready: ["可执行", "success"],
  queued: ["排队中", "accent"],
  running: ["运行中", "info"],
  failed: ["失败", "danger"],
  paused: ["已暂停", "neutral"],
};

const ACCOUNT_STATUS = {
  available: ["可用", "success"],
  bound_current: ["当前绑定", "accent"],
  bound_next: ["下一账号", "info"],
  exited_pending: ["退出待处理", "warning"],
  retired: ["已退役", "neutral"],
  disabled: ["已停用", "danger"],
};

const INVENTORY_STATUS = {
  available: ["可用", "success"],
  disabled: ["已禁用", "danger"],
  exhausted: ["已耗尽", "warning"],
};

const RUN_STATUS = {
  queued: ["排队中", "accent"],
  running: ["运行中", "info"],
  stopping: ["正在停止", "warning"],
  succeeded: ["成功", "success"],
  failed: ["失败", "danger"],
  cancelled: ["已停止", "neutral"],
};

const QUEUE_STATUS = {
  queued: "等待执行",
  pending: "等待执行",
  running: "运行中",
  stopping: "正在停止",
  failed: "失败",
  completed: "已完成",
  succeeded: "已完成",
  cancelled: "已停止",
};

const VIEW_NAMES = new Set(["spaces", "accounts", "runs", "settings"]);
const ACTIVE_RUN_STATES = new Set(["running", "stopping"]);
const ACTIVE_QUEUE_STATES = new Set(["queued", "pending", "running", "stopping"]);
const MAX_DIAGNOSTIC_ROWS = 300;
const MAX_EVENT_MEMORY = 1000;
const ACCOUNT_PAGE_SIZE = 50;
const MOBILE_ACCOUNT_PAGE_SIZE = 20;
const INVENTORY_SEARCH_LIMIT = 20;
const INVENTORY_SEARCH_DELAY = 300;

const dateTimeFormatter = new Intl.DateTimeFormat("zh-CN", {
  month: "2-digit",
  day: "2-digit",
  hour: "2-digit",
  minute: "2-digit",
  second: "2-digit",
  hour12: false,
});
const numberFormatter = new Intl.NumberFormat("zh-CN");

const state = {
  requestToken: "",
  view: "spaces",
  workspaces: [],
  accounts: [],
  runs: [],
  queue: {items: [], paused: false},
  settings: {},
  migration: null,
  migrationBlocked: false,
  selectedWorkspaceIds: new Set(),
  filters: {
    workspaceSearch: "",
    workspaceStatus: "all",
    accountSearch: "",
    accountStatus: "all",
    runSearch: "",
    runState: "all",
    runDateFrom: "",
  },
  errors: {},
  settingsDirty: false,
  sub2apiGroups: [],
  clearSecrets: new Set(),
  queueExpanded: false,
  accountPage: 1,
  accountView: "used",
  inventoryResults: [],
  inventoryQuery: "",
  inventoryStatus: "available",
  inventoryLoading: false,
  inventoryError: "",
  inventoryDirty: false,
  inventorySearchTimer: null,
  inventoryRequestController: null,
  inventorySearchSequence: 0,
  activeRunId: null,
  activeRun: null,
  activeRunEvents: [],
  eventSource: null,
  lastEventSequence: 0,
};
let requestTokenRefreshPromise = null;

const comboboxes = new Map(["current", "next"].map((role) => [role, {
  role,
  selected: null,
  original: null,
  query: "",
  inventoryResults: [],
  loading: false,
  error: "",
  open: false,
  activeIndex: -1,
  searchTimer: null,
  requestController: null,
  searchSequence: 0,
}]));

class ApiError extends Error {
  constructor(message, {status = 0, code = "request_failed", fields = null} = {}) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.code = code;
    this.fields = fields;
  }
}

const byId = (id) => document.getElementById(id);

function element(tag, options = {}, children = []) {
  const node = document.createElement(tag);
  if (options.className) node.className = options.className;
  if (options.text !== undefined && options.text !== null) node.textContent = String(options.text);
  if (options.dataset) {
    for (const [name, value] of Object.entries(options.dataset)) {
      if (value !== undefined && value !== null) node.dataset[name] = String(value);
    }
  }
  if (options.attrs) {
    for (const [name, value] of Object.entries(options.attrs)) {
      if (value === false || value === null || value === undefined) continue;
      node.setAttribute(name, value === true ? "" : String(value));
    }
  }
  const list = Array.isArray(children) ? children : [children];
  for (const child of list) {
    if (child === null || child === undefined) continue;
    node.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
  return node;
}

function actionButton(label, action, dataset = {}, className = "text-action") {
  return element("button", {
    className,
    text: label,
    dataset: {action, ...dataset},
    attrs: {type: "button"},
  });
}

function statusBadge(status, definitions) {
  const [label, tone] = definitions[status] || [status || "未知", "neutral"];
  return element("span", {
    className: "status-badge",
    text: label,
    dataset: {tone},
  });
}

function safeString(value, fallback = "") {
  if (value === null || value === undefined) return fallback;
  return String(value);
}

function booleanValue(value) {
  if (typeof value === "boolean") return value;
  if (typeof value === "number") return value !== 0;
  return ["1", "true", "yes", "on"].includes(safeString(value).trim().toLowerCase());
}

function firstValue(object, keys, fallback = "") {
  if (!object || typeof object !== "object") return fallback;
  for (const key of keys) {
    const value = object[key];
    if (value !== null && value !== undefined && value !== "") return value;
  }
  return fallback;
}

function asList(payload, keys = []) {
  if (Array.isArray(payload)) return payload;
  if (!payload || typeof payload !== "object") return [];
  for (const key of [...keys, "items", "data", "results"]) {
    if (Array.isArray(payload[key])) return payload[key];
  }
  return [];
}

function normalizeQueue(payload) {
  if (Array.isArray(payload)) return {items: payload, paused: false};
  const source = payload && typeof payload === "object" ? payload : {};
  return {
    items: asList(source, ["queue", "queue_items"]),
    paused: Boolean(firstValue(source, ["paused", "is_paused"], false)),
  };
}

function normalizedError(payload, status) {
  const source = payload && typeof payload === "object" ? payload : {};
  const detail = source.detail;
  let message = "";
  if (typeof detail === "string") message = detail;
  if (!message && detail && typeof detail === "object") {
    message = safeString(firstValue(detail, ["message", "detail", "error"]));
  }
  if (!message) message = safeString(firstValue(source, ["message", "error"]));
  if (!message) message = `请求失败 (${status})`;
  const code = safeString(firstValue(source, ["code", "error_code"], firstValue(detail, ["code"], "request_failed")));
  const fields = source.fields || source.field_errors || (detail && detail.fields) || null;
  return new ApiError(message, {status, code, fields});
}

async function refreshRequestToken() {
  if (requestTokenRefreshPromise) return requestTokenRefreshPromise;
  requestTokenRefreshPromise = (async () => {
    const response = await fetch("/api/bootstrap", {
      cache: "no-store",
      credentials: "same-origin",
    });
    const payload = await response.json();
    if (!response.ok) throw normalizedError(payload, response.status);
    const token = safeString(firstValue(payload, ["request_token", "csrf_token", "token"]));
    if (!token) throw new ApiError("本地服务未返回请求令牌", {code: "missing_request_token"});
    state.requestToken = token;
    return token;
  })();
  try {
    return await requestTokenRefreshPromise;
  } finally {
    requestTokenRefreshPromise = null;
  }
}

async function api(path, options = {}) {
  const controller = new AbortController();
  const timeout = Number(options.timeout || 20000);
  let timedOut = false;
  const timer = window.setTimeout(() => {
    timedOut = true;
    controller.abort();
  }, timeout);
  const headers = new Headers(options.headers || {});
  headers.set("Accept", "application/json");
  if (state.requestToken) headers.set("X-Workflow-Token", state.requestToken);

  let body = options.body;
  if (body !== undefined && body !== null && !(body instanceof FormData) && typeof body !== "string") {
    headers.set("Content-Type", "application/json");
    body = JSON.stringify(body);
  }

  if (options.signal) {
    if (options.signal.aborted) controller.abort();
    options.signal.addEventListener("abort", () => controller.abort(), {once: true});
  }

  try {
    const response = await fetch(path, {
      method: options.method || "GET",
      headers,
      body,
      signal: controller.signal,
      cache: "no-store",
      credentials: "same-origin",
    });
    if (response.status === 204) return null;
    const contentType = response.headers.get("content-type") || "";
    let payload = null;
    if (contentType.includes("application/json")) {
      payload = await response.json();
    } else {
      const text = await response.text();
      payload = text ? {detail: text} : null;
    }
    if (!response.ok) {
      const error = normalizedError(payload, response.status);
      if (
        response.status === 403
        && error.code === "invalid_request_token"
        && !options.requestTokenRetried
      ) {
        await refreshRequestToken();
        connectEvents();
        return api(path, {...options, requestTokenRetried: true});
      }
      throw error;
    }
    return payload;
  } catch (error) {
    if (error?.name === "AbortError") {
      if (!timedOut && options.signal?.aborted) {
        throw new ApiError("请求已取消", {code: "request_cancelled"});
      }
      throw new ApiError("请求超时，请检查本地服务后重试", {code: "request_timeout"});
    }
    throw error;
  } finally {
    window.clearTimeout(timer);
  }
}

function isMigrationError(error) {
  const code = safeString(error?.code).toLowerCase();
  const message = safeString(error?.message).toLowerCase();
  return error?.status === 503 && (code.includes("migration") || message.includes("迁移") || message.includes("cleanup"));
}

function setConnection(connectionState, label) {
  const container = byId("connection-status");
  container.dataset.state = connectionState;
  byId("connection-label").textContent = label;
}

function showToast(message, level = "info") {
  const region = byId("toast-region");
  const toast = element("div", {className: "toast", text: message, dataset: {level}});
  region.append(toast);
  while (region.children.length > 3) region.firstElementChild.remove();
  window.setTimeout(() => toast.remove(), 3600);
}

function showMigrationBlocked(message, migration = null) {
  state.migrationBlocked = true;
  state.migration = migration || state.migration;
  byId("migration-message").textContent = message || "普通操作已锁定，完成清理后即可继续。";
  byId("migration-banner").hidden = false;
}

function clearMigrationBlocked() {
  state.migrationBlocked = false;
  byId("migration-banner").hidden = true;
}

function ensureMutable() {
  if (!state.migrationBlocked) return true;
  showToast("迁移清理完成前不能修改数据", "error");
  return false;
}

function currentViewFromHash() {
  const candidate = window.location.hash.replace(/^#/, "");
  return VIEW_NAMES.has(candidate) ? candidate : "spaces";
}

function selectView(viewName) {
  state.view = VIEW_NAMES.has(viewName) ? viewName : "spaces";
  for (const view of document.querySelectorAll("[data-view]")) {
    const active = view.dataset.view === state.view;
    view.classList.toggle("is-active", active);
    view.hidden = !active;
  }
  for (const link of document.querySelectorAll("[data-view-link]")) {
    const active = link.dataset.viewLink === state.view;
    link.classList.toggle("is-active", active);
    if (active) link.setAttribute("aria-current", "page");
    else link.removeAttribute("aria-current");
  }
}

function formatDate(value) {
  if (!value) return "-";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? safeString(value) : dateTimeFormatter.format(date);
}

function formatDuration(run) {
  const direct = Number(firstValue(run, ["duration_seconds", "duration"], 0));
  if (Number.isFinite(direct) && direct > 0) return `${numberFormatter.format(Math.round(direct))} 秒`;
  const start = new Date(firstValue(run, ["started_at", "created_at"], ""));
  const end = new Date(firstValue(run, ["finished_at", "updated_at"], ""));
  if (Number.isNaN(start.getTime()) || Number.isNaN(end.getTime())) return "-";
  const seconds = Math.max(0, Math.round((end.getTime() - start.getTime()) / 1000));
  return `${numberFormatter.format(seconds)} 秒`;
}

function shortId(value) {
  const text = safeString(value, "-");
  return text.length > 16 ? `${text.slice(0, 8)}…${text.slice(-4)}` : text;
}

function workspaceId(workspace) {
  return safeString(firstValue(workspace, ["id", "workspace_id"]));
}

function workspaceUid(workspace) {
  return safeString(firstValue(workspace, ["workspace_uid", "uid", "external_id"]), "-");
}

function workspaceName(workspace) {
  return safeString(firstValue(workspace, ["name", "workspace_name"], "未命名空间"));
}

function accountId(account) {
  return safeString(firstValue(account, ["id", "account_id"]));
}

function accountEmail(account) {
  return safeString(firstValue(account, ["email", "account_email", "primary_email"], "未提供邮箱"));
}

function runId(run) {
  return safeString(firstValue(run, ["id", "run_id"]));
}

function findAccount(id) {
  return state.accounts.find((account) => accountId(account) === safeString(id));
}

function findWorkspace(id) {
  return state.workspaces.find((workspace) => workspaceId(workspace) === safeString(id));
}

function workspaceAccountLabel(workspace, role) {
  const nested = workspace?.[`${role}_account`];
  if (nested && typeof nested === "object") return accountEmail(nested);
  const explicit = firstValue(workspace, [`${role}_email`, `${role}_account_email`]);
  if (explicit) return safeString(explicit);
  const id = firstValue(workspace, [`${role}_account_id`]);
  const account = findAccount(id);
  return account ? accountEmail(account) : "未分配";
}

function workspaceSearchText(workspace) {
  return [
    workspaceName(workspace),
    workspaceUid(workspace),
    workspaceAccountLabel(workspace, "current"),
    workspaceAccountLabel(workspace, "next"),
  ].join(" ").toLocaleLowerCase("zh-CN");
}

function filteredWorkspaces() {
  const search = state.filters.workspaceSearch.trim().toLocaleLowerCase("zh-CN");
  return state.workspaces.filter((workspace) => {
    const status = safeString(firstValue(workspace, ["status", "state"]));
    const statusMatch = state.filters.workspaceStatus === "all" || status === state.filters.workspaceStatus;
    return statusMatch && (!search || workspaceSearchText(workspace).includes(search));
  });
}

function loadingOrErrorRow(columnCount, resource, emptyMessage) {
  const error = state.errors[resource];
  const row = element("tr", {className: error ? "error-row" : "empty-row"});
  const cell = element("td", {
    text: error ? `${error}。请刷新页面或检查本地服务。` : emptyMessage,
    attrs: {colspan: columnCount},
  });
  row.append(cell);
  return row;
}

function labeledCell(label, child, className = "") {
  const cell = element("td", {className, attrs: {"data-label": label}});
  if (child instanceof Node) cell.append(child);
  else cell.textContent = safeString(child, "-");
  return cell;
}

function primarySecondary(primary, secondary = "") {
  const wrap = element("div");
  wrap.append(element("span", {className: "cell-primary", text: primary}));
  if (secondary) wrap.append(element("span", {className: "cell-secondary", text: secondary}));
  return wrap;
}

function renderWorkspaceMetrics() {
  const counts = {total: state.workspaces.length, ready: 0, needs: 0, attention: 0};
  for (const workspace of state.workspaces) {
    const status = safeString(firstValue(workspace, ["status", "state"]));
    if (status === "ready") counts.ready += 1;
    if (status === "needs_account") counts.needs += 1;
    if (status === "failed" || status === "paused") counts.attention += 1;
  }
  byId("metric-total").textContent = numberFormatter.format(counts.total);
  byId("metric-ready").textContent = numberFormatter.format(counts.ready);
  byId("metric-needs-account").textContent = numberFormatter.format(counts.needs);
  byId("metric-attention").textContent = numberFormatter.format(counts.attention);
}

function renderWorkspaceTable() {
  renderWorkspaceMetrics();
  const body = byId("workspace-table-body");
  const visible = filteredWorkspaces();
  const existingIds = new Set(state.workspaces.map(workspaceId));
  for (const id of [...state.selectedWorkspaceIds]) {
    if (!existingIds.has(id)) state.selectedWorkspaceIds.delete(id);
  }

  body.replaceChildren();
  if (!visible.length) {
    body.append(loadingOrErrorRow(8, "workspaces", state.workspaces.length ? "没有符合筛选条件的空间" : "尚未添加空间"));
  } else {
    const fragment = document.createDocumentFragment();
    for (const workspace of visible) {
      const id = workspaceId(workspace);
      const status = safeString(firstValue(workspace, ["status", "state"], "needs_account"));
      const selectable = status === "ready";
      const row = element("tr", {dataset: {workspaceId: id}});
      row.classList.toggle("is-selected", state.selectedWorkspaceIds.has(id));

      const checkbox = element("input", {
        attrs: {type: "checkbox", "aria-label": `选择 ${workspaceName(workspace)}`},
        dataset: {workspaceSelect: id},
      });
      checkbox.checked = state.selectedWorkspaceIds.has(id);
      checkbox.disabled = !selectable;
      const check = element("label", {className: "check-control check-control--solo"}, [
        checkbox,
        element("span", {attrs: {"aria-hidden": "true"}}),
      ]);
      row.append(labeledCell("选择", check, "selection-cell"));

      const rotationCount = Number(firstValue(workspace, ["rotation_count"], 0));
      row.append(labeledCell("空间", primarySecondary(workspaceName(workspace), `轮换 ${numberFormatter.format(rotationCount)} 次`)));

      const uid = workspaceUid(workspace);
      const uidNode = element("span", {className: "cell-code", text: shortId(uid), attrs: {title: uid}});
      row.append(labeledCell("Workspace ID", uidNode));

      const current = workspaceAccountLabel(workspace, "current");
      const next = workspaceAccountLabel(workspace, "next");
      row.append(labeledCell("当前账号", element("span", {className: current === "未分配" ? "empty-value" : "cell-primary", text: current, attrs: {title: current}})));
      row.append(labeledCell("下一账号", element("span", {className: next === "未分配" ? "empty-value" : "cell-primary", text: next, attrs: {title: next}})));
      row.append(labeledCell("状态", statusBadge(status, WORKSPACE_STATUS)));

      const lastState = safeString(firstValue(workspace, ["last_run_state", "last_state", "last_result"]));
      const lastTime = firstValue(workspace, ["last_run_at", "last_finished_at", "updated_at"]);
      const lastRun = primarySecondary(lastState ? (RUN_STATUS[lastState]?.[0] || lastState) : "尚未运行", lastState ? formatDate(lastTime) : "");
      const lastError = safeString(firstValue(workspace, ["last_error", "redacted_error"]));
      if (lastError) lastRun.append(element("span", {className: "cell-error", text: lastError, attrs: {title: lastError}}));
      row.append(labeledCell("最近运行", lastRun));

      const actions = element("div", {className: "row-actions"});
      actions.append(actionButton("编辑", "edit-workspace", {workspaceId: id}));
      if (status === "ready" && next !== "未分配") {
        actions.append(actionButton("额度用完", "advance-workspace", {workspaceId: id}));
      }
      if (status === "failed") actions.append(actionButton("重试", "retry-workspace", {workspaceId: id}));
      const lastRunId = safeString(firstValue(workspace, ["last_run_id"]));
      if (lastRunId) actions.append(actionButton("详情", "open-run-detail", {runId: lastRunId}));
      row.append(labeledCell("操作", actions, "actions-cell"));
      fragment.append(row);
    }
    body.append(fragment);
  }

  const visibleReadyIds = visible
    .filter((workspace) => safeString(firstValue(workspace, ["status", "state"])) === "ready")
    .map(workspaceId);
  const selectedVisible = visibleReadyIds.filter((id) => state.selectedWorkspaceIds.has(id)).length;
  const selectAll = byId("select-all-workspaces");
  selectAll.checked = visibleReadyIds.length > 0 && selectedVisible === visibleReadyIds.length;
  selectAll.indeterminate = selectedVisible > 0 && selectedVisible < visibleReadyIds.length;
  selectAll.disabled = visibleReadyIds.length === 0;
  byId("workspace-selection-count").textContent = `已选 ${numberFormatter.format(state.selectedWorkspaceIds.size)} 项`;
  byId("enqueue-selected").disabled = state.selectedWorkspaceIds.size === 0;
}

function accountBindingLabel(account) {
  const binding = accountBinding(account);
  return binding ? workspaceName(binding.workspace) : "未绑定";
}

function accountBinding(account) {
  const direct = firstValue(account, ["workspace_name", "bound_workspace_name"]);
  const directId = firstValue(account, ["workspace_id", "bound_workspace_id"]);
  const directRole = safeString(firstValue(account, ["workspace_role", "bound_role", "role"]));
  if (directId) {
    const workspace = findWorkspace(directId);
    if (workspace) return {workspace, role: directRole || (safeString(workspace.current_account_id) === accountId(account) ? "current" : "next")};
  }
  const accountIdentifier = accountId(account);
  const workspace = state.workspaces.find((candidate) => {
    return safeString(candidate.current_account_id) === accountIdentifier || safeString(candidate.next_account_id) === accountIdentifier;
  });
  if (workspace) {
    return {
      workspace,
      role: safeString(workspace.current_account_id) === accountIdentifier ? "current" : "next",
    };
  }
  if (direct) return {workspace: {name: safeString(direct), id: safeString(directId)}, role: directRole};
  return null;
}

function renderAccountMetrics() {
  let available = 0;
  let pending = 0;
  let bound = 0;
  for (const account of state.accounts) {
    const status = safeString(firstValue(account, ["status", "state"]));
    if (status === "available") available += 1;
    if (status === "exited_pending") pending += 1;
    if (status === "bound_current" || status === "bound_next") bound += 1;
  }
  byId("account-metric-total").textContent = numberFormatter.format(state.accounts.length);
  byId("account-metric-available").textContent = numberFormatter.format(available);
  byId("account-metric-pending").textContent = numberFormatter.format(pending);
  byId("account-metric-bound").textContent = numberFormatter.format(bound);
}

function filteredAccounts() {
  const search = state.filters.accountSearch.trim().toLocaleLowerCase("zh-CN");
  return state.accounts.filter((account) => {
    const status = safeString(firstValue(account, ["status", "state"]));
    const statusMatch = state.filters.accountStatus === "all" || status === state.filters.accountStatus;
    const haystack = `${accountEmail(account)} ${safeString(account.primary_email)} ${accountBindingLabel(account)}`.toLocaleLowerCase("zh-CN");
    return statusMatch && (!search || haystack.includes(search));
  });
}

function accountPageSize() {
  return window.matchMedia("(max-width: 820px)").matches ? MOBILE_ACCOUNT_PAGE_SIZE : ACCOUNT_PAGE_SIZE;
}

function renderAccountTable() {
  renderAccountMetrics();
  const body = byId("account-table-body");
  const visible = filteredAccounts();
  const pageSize = accountPageSize();
  const totalPages = Math.max(1, Math.ceil(visible.length / pageSize));
  state.accountPage = Math.min(Math.max(1, state.accountPage), totalPages);
  const startIndex = (state.accountPage - 1) * pageSize;
  const pageAccounts = visible.slice(startIndex, startIndex + pageSize);
  body.replaceChildren();
  if (!pageAccounts.length) {
    body.append(loadingOrErrorRow(7, "accounts", state.accounts.length ? "没有符合筛选条件的账号" : "尚未分配任何子号"));
  } else {
    const fragment = document.createDocumentFragment();
    for (const account of pageAccounts) {
      const id = accountId(account);
      const status = safeString(firstValue(account, ["status", "state"], "available"));
      const row = element("tr", {dataset: {accountId: id}});
      const email = accountEmail(account);
      row.append(labeledCell("邮箱", element("span", {className: "cell-primary", text: email, attrs: {title: email}})));
      row.append(labeledCell("主邮箱", element("span", {className: "cell-secondary", text: safeString(account.primary_email, email), attrs: {title: safeString(account.primary_email, email)}})));
      row.append(labeledCell("状态", statusBadge(status, ACCOUNT_STATUS)));
      row.append(labeledCell("绑定空间", accountBindingLabel(account)));
      row.append(labeledCell("来源", safeString(firstValue(account, ["source"], "import"))));
      row.append(labeledCell("更新时间", formatDate(firstValue(account, ["updated_at", "created_at"]))));
      const actions = element("div", {className: "row-actions"});
      const binding = accountBinding(account);
      if (binding && ["bound_current", "bound_next"].includes(status)) {
        actions.append(actionButton("不可用", "invalidate-bound-account", {
          accountId: id,
          failureType: "alias_disabled",
        }));
        actions.append(actionButton("封禁邮箱", "invalidate-bound-account", {
          accountId: id,
          failureType: "mailbox_credentials_invalid",
        }, "text-action text-action--danger"));
      } else if (status === "exited_pending" || status === "disabled") {
        actions.append(actionButton("重新启用", "set-account-status", {accountId: id, status: "available"}));
      }
      if (!binding && (status === "exited_pending" || status === "available")) {
        actions.append(actionButton("退役", "set-account-status", {accountId: id, status: "retired"}, "text-action text-action--danger"));
      }
      if (!binding && status === "available") {
        actions.append(actionButton("停用", "set-account-status", {accountId: id, status: "disabled"}));
      }
      if (!actions.children.length) actions.append(element("span", {className: "empty-value", text: "-"}));
      row.append(labeledCell("操作", actions, "actions-cell"));
      fragment.append(row);
    }
    body.append(fragment);
  }

  const visibleStart = visible.length ? startIndex + 1 : 0;
  const visibleEnd = Math.min(startIndex + pageAccounts.length, visible.length);
  byId("account-page-summary").textContent = `第 ${numberFormatter.format(visibleStart)}-${numberFormatter.format(visibleEnd)} 条，共 ${numberFormatter.format(visible.length)} 条`;
  byId("account-page-indicator").textContent = `${numberFormatter.format(state.accountPage)} / ${numberFormatter.format(totalPages)}`;
  document.querySelector('[data-action="account-page-prev"]').disabled = state.accountPage <= 1;
  document.querySelector('[data-action="account-page-next"]').disabled = state.accountPage >= totalPages;
}

function changeAccountPage(delta) {
  const totalPages = Math.max(1, Math.ceil(filteredAccounts().length / accountPageSize()));
  const nextPage = Math.min(Math.max(1, state.accountPage + delta), totalPages);
  if (nextPage === state.accountPage) return;
  state.accountPage = nextPage;
  renderAccountTable();
  byId("view-accounts").querySelector(".table-toolbar").scrollIntoView({block: "start"});
}

function inventoryId(item) {
  return safeString(firstValue(item, ["id", "inventory_id"]));
}

function inventoryEmail(item) {
  return safeString(firstValue(item, ["primary_email", "email"], "未知邮箱"));
}

function inventoryAliasNumber(item) {
  return Number(firstValue(item, ["next_alias_number", "next_alias"], 0));
}

function inventoryAliasEmail(item) {
  const primary = inventoryEmail(item);
  const aliasNumber = inventoryAliasNumber(item);
  const at = primary.lastIndexOf("@");
  if (at <= 0 || aliasNumber < 1 || aliasNumber > 5) return "无可分配子号";
  return `${primary.slice(0, at)}+${aliasNumber}${primary.slice(at)}`;
}

function renderAccountView() {
  const used = state.accountView === "used";
  byId("account-used-panel").hidden = !used;
  byId("account-inventory-panel").hidden = used;
  for (const tab of document.querySelectorAll("[data-account-view]")) {
    const active = tab.dataset.accountView === state.accountView;
    tab.classList.toggle("is-active", active);
    tab.setAttribute("aria-selected", String(active));
    tab.tabIndex = active ? 0 : -1;
  }
  if (used) renderAccountTable();
  else renderInventoryTable();
}

function selectAccountView(view) {
  state.accountView = view === "inventory" ? "inventory" : "used";
  if (state.accountView === "used") {
    cancelInventorySearch();
  } else if (state.inventoryDirty && state.inventoryQuery.trim()) {
    scheduleInventorySearch({immediate: true});
  }
  renderAccountView();
}

function renderInventoryTable() {
  const body = byId("inventory-table-body");
  const status = byId("inventory-search-status");
  body.replaceChildren();
  if (!state.inventoryQuery.trim()) {
    body.append(loadingOrErrorRow(5, "inventory", "输入邮箱搜索库存"));
    status.textContent = "输入邮箱后搜索，最多显示 20 条";
    return;
  }
  if (state.inventoryLoading) {
    const row = element("tr", {className: "loading-row"});
    row.append(element("td", {attrs: {colspan: "5"}}, [
      element("span", {className: "inline-loader", attrs: {"aria-hidden": "true"}}),
      "正在搜索库存…",
    ]));
    body.append(row);
    status.textContent = "正在搜索…";
    return;
  }
  if (state.inventoryError) {
    const row = element("tr", {className: "error-row"});
    row.append(element("td", {text: `${state.inventoryError}。请修改关键词后重试。`, attrs: {colspan: "5"}}));
    body.append(row);
    status.textContent = "搜索失败";
    return;
  }
  if (!state.inventoryResults.length) {
    body.append(loadingOrErrorRow(5, "inventory", "未找到匹配的邮箱库存"));
    status.textContent = "0 条结果";
    return;
  }
  const fragment = document.createDocumentFragment();
  for (const item of state.inventoryResults.slice(0, INVENTORY_SEARCH_LIMIT)) {
    const itemStatus = safeString(firstValue(item, ["status", "state"], "available"));
    const aliasNumber = inventoryAliasNumber(item);
    const row = element("tr", {dataset: {inventoryId: inventoryId(item)}});
    row.append(labeledCell("主邮箱", element("span", {className: "cell-primary", text: inventoryEmail(item), attrs: {title: inventoryEmail(item)}})));
    row.append(labeledCell("状态", statusBadge(itemStatus, INVENTORY_STATUS)));
    row.append(labeledCell("下一个子号", element("span", {className: "cell-code", text: aliasNumber >= 1 && aliasNumber <= 5 ? `+${aliasNumber}` : "-"})));
    const failure = safeString(firstValue(item, ["failure_message", "redacted_failure", "failure_code"], "-"));
    row.append(labeledCell("最近失效", element("span", {className: failure === "-" ? "empty-value" : "cell-error", text: failure, attrs: {title: failure}})));
    const actions = element("div", {className: "row-actions"});
    const allocate = actionButton("分配子号", "open-inventory-allocation", {inventoryId: inventoryId(item)});
    allocate.disabled = itemStatus !== "available" || aliasNumber < 1 || aliasNumber > 5;
    actions.append(allocate);
    row.append(labeledCell("操作", actions, "actions-cell"));
    fragment.append(row);
  }
  body.append(fragment);
  status.textContent = `${numberFormatter.format(state.inventoryResults.length)} 条结果，最多显示 ${INVENTORY_SEARCH_LIMIT} 条`;
}

function cancelInventorySearch() {
  if (state.inventorySearchTimer) window.clearTimeout(state.inventorySearchTimer);
  state.inventorySearchTimer = null;
  state.inventoryRequestController?.abort();
  state.inventoryRequestController = null;
  state.inventoryLoading = false;
  state.inventorySearchSequence += 1;
}

function scheduleInventorySearch({immediate = false} = {}) {
  cancelInventorySearch();
  const query = state.inventoryQuery.trim();
  if (!query) {
    state.inventoryResults = [];
    state.inventoryError = "";
    renderInventoryTable();
    return;
  }
  state.inventoryLoading = true;
  renderInventoryTable();
  state.inventorySearchTimer = window.setTimeout(() => {
    state.inventorySearchTimer = null;
    searchInventory().catch(() => {});
  }, immediate ? 0 : INVENTORY_SEARCH_DELAY);
}

async function searchInventory() {
  const query = state.inventoryQuery.trim();
  if (!query) return;
  const sequence = ++state.inventorySearchSequence;
  const controller = new AbortController();
  state.inventoryRequestController = controller;
  state.inventoryLoading = true;
  state.inventoryError = "";
  renderInventoryTable();
  const params = new URLSearchParams({query, limit: String(INVENTORY_SEARCH_LIMIT)});
  if (state.inventoryStatus !== "all") params.set("status", state.inventoryStatus);
  try {
    const payload = await api(`/api/mailbox-inventory?${params.toString()}`, {signal: controller.signal});
    if (sequence !== state.inventorySearchSequence) return;
    state.inventoryResults = asList(payload, ["inventory", "mailbox_inventory"]).slice(0, INVENTORY_SEARCH_LIMIT);
    state.inventoryDirty = false;
  } catch (error) {
    if (error?.code === "request_cancelled" || sequence !== state.inventorySearchSequence) return;
    state.inventoryError = error?.message || String(error);
    state.inventoryResults = [];
  } finally {
    if (sequence === state.inventorySearchSequence) {
      state.inventoryLoading = false;
      state.inventoryRequestController = null;
      renderInventoryTable();
    }
  }
}

function runWorkspaceLabel(run) {
  const direct = firstValue(run, ["workspace_name", "name"]);
  if (direct) return safeString(direct);
  const workspace = findWorkspace(firstValue(run, ["workspace_id"]));
  return workspace ? workspaceName(workspace) : shortId(firstValue(run, ["workspace_uid_snapshot", "workspace_id"], "未知空间"));
}

function runAccountSnapshot(run) {
  const current = safeString(firstValue(run, ["current_email_snapshot", "current_email"], "未知账号"));
  const next = safeString(firstValue(run, ["next_email_snapshot", "next_email"], "未知账号"));
  return [current, next];
}

function filteredRuns() {
  const search = state.filters.runSearch.trim().toLocaleLowerCase("zh-CN");
  const from = state.filters.runDateFrom ? new Date(`${state.filters.runDateFrom}T00:00:00`) : null;
  return state.runs.filter((run) => {
    const runState = safeString(firstValue(run, ["state", "status"]));
    if (state.filters.runState !== "all" && runState !== state.filters.runState) return false;
    if (from) {
      const created = new Date(firstValue(run, ["started_at", "created_at"], ""));
      if (!Number.isNaN(created.getTime()) && created < from) return false;
    }
    const [current, next] = runAccountSnapshot(run);
    const haystack = `${runId(run)} ${runWorkspaceLabel(run)} ${current} ${next}`.toLocaleLowerCase("zh-CN");
    return !search || haystack.includes(search);
  });
}

function renderRunTable() {
  const body = byId("run-table-body");
  const visible = filteredRuns();
  body.replaceChildren();
  if (!visible.length) {
    body.append(loadingOrErrorRow(7, "runs", state.runs.length ? "没有符合筛选条件的运行记录" : "尚无运行记录"));
    return;
  }
  const fragment = document.createDocumentFragment();
  for (const run of visible) {
    const id = runId(run);
    const runState = safeString(firstValue(run, ["state", "status"], "queued"));
    const [current, next] = runAccountSnapshot(run);
    const row = element("tr", {dataset: {runId: id}});
    row.append(labeledCell("空间", primarySecondary(runWorkspaceLabel(run), shortId(id))));
    row.append(labeledCell("账号快照", primarySecondary(current, `下一账号：${next}`)));
    row.append(labeledCell("结果", statusBadge(runState, RUN_STATUS)));
    const step = safeString(firstValue(run, ["current_step", "step"]));
    row.append(labeledCell("当前阶段", STEP_LABELS[step] || (runState === "succeeded" ? "全部完成" : step || "等待开始")));
    row.append(labeledCell("开始时间", formatDate(firstValue(run, ["started_at", "created_at"]))));
    row.append(labeledCell("耗时", formatDuration(run)));
    const actions = element("div", {className: "row-actions"}, [actionButton("查看", "open-run-detail", {runId: id})]);
    row.append(labeledCell("详情", actions, "actions-cell"));
    fragment.append(row);
  }
  body.append(fragment);
}

function queueItemState(item) {
  return safeString(firstValue(item, ["state", "status"], "queued"));
}

function queueItemRunId(item) {
  return safeString(firstValue(item, ["run_id", "id"]));
}

function queueItemWorkspaceName(item) {
  const direct = firstValue(item, ["workspace_name", "name"]);
  if (direct) return safeString(direct);
  const run = item.run && typeof item.run === "object" ? item.run : state.runs.find((candidate) => runId(candidate) === queueItemRunId(item));
  if (run) return runWorkspaceLabel(run);
  const workspace = findWorkspace(firstValue(item, ["workspace_id"]));
  return workspace ? workspaceName(workspace) : "未知空间";
}

function activeQueueItems() {
  return state.queue.items
    .filter((item) => ACTIVE_QUEUE_STATES.has(queueItemState(item)))
    .sort((left, right) => Number(firstValue(left, ["position"], 0)) - Number(firstValue(right, ["position"], 0)));
}

function renderQueue() {
  const drawer = byId("queue-drawer");
  drawer.dataset.expanded = String(state.queueExpanded);
  const toggle = drawer.querySelector("[data-action='toggle-queue']");
  toggle.setAttribute("aria-expanded", String(state.queueExpanded));
  byId("queue-body").hidden = !state.queueExpanded;

  const items = activeQueueItems();
  const running = items.find((item) => ACTIVE_RUN_STATES.has(queueItemState(item)));
  const pendingCount = items.filter((item) => ["queued", "pending"].includes(queueItemState(item))).length;
  byId("queue-summary").textContent = `${numberFormatter.format(pendingCount)} 项待执行`;
  byId("queue-running-summary").textContent = running
    ? `正在运行：${queueItemWorkspaceName(running)}`
    : state.queue.paused ? "队列已暂停" : "当前无运行任务";
  byId("queue-state").textContent = state.queue.paused
    ? "队列已暂停，不会领取新任务。"
    : running ? "全局顺序执行中，每次仅运行 1 个空间。" : "队列就绪。";
  byId("queue-pause-button").textContent = state.queue.paused ? "继续队列" : "暂停队列";

  const list = byId("queue-list");
  list.replaceChildren();
  if (!items.length) {
    list.append(element("li", {className: "empty-state", text: state.errors.queue || "队列为空"}));
    return;
  }
  const fragment = document.createDocumentFragment();
  items.forEach((item, index) => {
    const itemState = queueItemState(item);
    const itemId = safeString(firstValue(item, ["id", "queue_item_id"]));
    const runIdentifier = queueItemRunId(item);
    const entry = element("li", {className: "queue-item", dataset: {state: itemState, queueItemId: itemId}});
    entry.append(element("span", {className: "queue-position", text: String(index + 1)}));
    entry.append(element("div", {className: "queue-item__copy"}, [
      element("strong", {text: queueItemWorkspaceName(item)}),
      element("span", {text: `${QUEUE_STATUS[itemState] || itemState} · ${shortId(runIdentifier)}`}),
    ]));
    const actions = element("div", {className: "queue-item__actions"});
    if (["queued", "pending"].includes(itemState)) {
      const up = actionButton("↑", "move-queue-item", {queueItemId: itemId, direction: "up"}, "queue-icon-button");
      up.setAttribute("aria-label", `上移 ${queueItemWorkspaceName(item)}`);
      up.disabled = index === 0;
      const down = actionButton("↓", "move-queue-item", {queueItemId: itemId, direction: "down"}, "queue-icon-button");
      down.setAttribute("aria-label", `下移 ${queueItemWorkspaceName(item)}`);
      down.disabled = index === items.length - 1 || ACTIVE_RUN_STATES.has(queueItemState(items[index + 1]));
      actions.append(up, down);
    }
    if (ACTIVE_RUN_STATES.has(itemState)) {
      const stop = actionButton("■", "stop-run", {runId: runIdentifier}, "queue-icon-button queue-icon-button--danger");
      stop.setAttribute("aria-label", `停止 ${queueItemWorkspaceName(item)}`);
      actions.append(stop);
    }
    entry.append(actions);
    fragment.append(entry);
  });
  list.append(fragment);
}

function configuredSecret(secrets, keys, fallback) {
  for (const key of keys) {
    if (Object.prototype.hasOwnProperty.call(secrets, key)) return booleanValue(secrets[key]);
  }
  return Boolean(fallback);
}

function safeSettings(payload, previous = {}) {
  const source = payload && typeof payload === "object" ? payload : {};
  const settings = source.values && typeof source.values === "object"
    ? source.values
    : source.settings && typeof source.settings === "object"
      ? source.settings
      : source;
  const secrets = source.secrets && typeof source.secrets === "object" ? source.secrets : source;
  return {
    output_dir: safeString(firstValue(settings, ["output_dir", "output_directory"])),
    pat_name: safeString(firstValue(settings, ["pat_name"])),
    pat_ttl: firstValue(settings, ["pat_ttl", "pat_ttl_seconds"], ""),
    invite_settle_seconds: firstValue(settings, ["invite_settle_seconds"], ""),
    management_url: safeString(firstValue(settings, ["management_base_url", "management_url"])),
    management_filename: safeString(firstValue(settings, ["management_remote_name", "management_filename", "remote_filename"])),
    management_push: booleanValue(firstValue(settings, ["management_push", "push_management"], false)),
    management_overwrite: booleanValue(firstValue(settings, ["management_replace", "management_overwrite", "overwrite_management"], false)),
    sub2api_url: safeString(firstValue(settings, ["sub2api_base_url", "sub2api_url"])),
    sub2api_email: safeString(firstValue(settings, ["sub2api_email"])),
    sub2api_push: booleanValue(firstValue(settings, ["sub2api_push", "push_sub2api"], false)),
    sub2api_concurrency: firstValue(settings, ["sub2api_concurrency"], ""),
    sub2api_priority: firstValue(settings, ["sub2api_priority"], ""),
    sub2api_group_id: firstValue(settings, ["sub2api_group_id"], ""),
    proxy_configured: configuredSecret(secrets, ["proxy", "proxy_configured", "proxy_present"], previous.proxy_configured),
    management_api_key_configured: configuredSecret(secrets, ["management_api_key", "management_api_key_configured", "management_key_present"], previous.management_api_key_configured),
    sub2api_password_configured: configuredSecret(secrets, ["sub2api_password", "sub2api_password_configured", "sub2api_password_present"], previous.sub2api_password_configured),
    sub2api_api_key_configured: configuredSecret(secrets, ["sub2api_api_key", "sub2api_api_key_configured", "sub2api_api_key_present"], previous.sub2api_api_key_configured),
    sub2api_totp_secret_configured: configuredSecret(secrets, ["sub2api_totp_secret", "sub2api_totp_secret_configured", "sub2api_totp_secret_present"], previous.sub2api_totp_secret_configured),
    last_backup_path: safeString(firstValue(settings, ["last_backup_path", "backup_path"])),
    last_backup_at: firstValue(settings, ["last_backup_at"]),
  };
}

function safeSub2APIGroups(payload) {
  return asList(payload, ["groups"])
    .map((item) => ({
      id: Number(firstValue(item, ["id"], 0)),
      name: safeString(firstValue(item, ["name"])).trim(),
      platform: safeString(firstValue(item, ["platform"])).trim().toLowerCase(),
      status: safeString(firstValue(item, ["status"], "active")).trim().toLowerCase(),
      is_exclusive: booleanValue(firstValue(item, ["is_exclusive"], false)),
    }))
    .filter((item) => Number.isInteger(item.id) && item.id > 0 && item.name);
}

function renderSub2APIGroupOptions(form, selectedValue) {
  const control = form.elements.namedItem("sub2api_group_id");
  if (!(control instanceof HTMLSelectElement)) return;
  const selected = safeString(selectedValue);
  const fragment = document.createDocumentFragment();
  fragment.append(element("option", {text: "默认分组", attrs: {value: ""}}));
  let selectedExists = !selected;
  for (const group of state.sub2apiGroups) {
    const compatible = group.platform === "openai" && group.status === "active";
    const isSelected = String(group.id) === selected;
    const label = [
      group.name,
      group.platform ? group.platform.toUpperCase() : "未指定平台",
      `ID ${group.id}`,
      group.status && group.status !== "active" ? group.status : "",
    ].filter(Boolean).join(" · ");
    const option = element("option", {
      text: label,
      attrs: {value: group.id, disabled: !compatible && !isSelected},
    });
    if (isSelected) selectedExists = true;
    fragment.append(option);
  }
  if (selected && !selectedExists) {
    fragment.append(element("option", {
      text: `已保存分组 · ID ${selected}`,
      attrs: {value: selected},
    }));
  }
  if (!state.sub2apiGroups.length) {
    fragment.append(element("option", {
      text: state.errors.sub2apiGroups ? "分组加载失败" : "没有可用分组",
      attrs: {disabled: true},
    }));
  }
  control.replaceChildren(fragment);
  control.value = selectedExists ? selected : "";
}

function renderSecretControls(form = byId("settings-form")) {
  const values = state.settings;
  const secretDefinitions = [
    ["proxy", "proxy-secret-state", "proxy_configured"],
    ["management_api_key", "management-secret-state", "management_api_key_configured"],
    ["sub2api_password", "sub2api-secret-state", "sub2api_password_configured"],
    ["sub2api_api_key", "sub2api-api-key-secret-state", "sub2api_api_key_configured"],
    ["sub2api_totp_secret", "sub2api-totp-secret-state", "sub2api_totp_secret_configured"],
  ];
  for (const [secret, statusId, configuredKey] of secretDefinitions) {
    const clearing = state.clearSecrets.has(secret);
    byId(statusId).textContent = clearing ? "保存时清除" : values[configuredKey] ? "已安全保存" : "未设置";
    const button = document.querySelector(`[data-action="toggle-secret-clear"][data-secret="${secret}"]`);
    if (button) {
      button.textContent = clearing ? "撤销清除" : "清除已保存值";
      button.closest(".secret-state-row").dataset.clearing = String(clearing);
      button.disabled = !clearing && !values[configuredKey];
    }
    const input = form.elements.namedItem(secret);
    if (input) input.disabled = clearing;
  }
}

function renderSettings({force = false} = {}) {
  if (state.settingsDirty && !force) return;
  const form = byId("settings-form");
  const values = state.settings;
  const textFields = [
    "output_dir",
    "pat_name",
    "pat_ttl",
    "invite_settle_seconds",
    "management_url",
    "management_filename",
    "sub2api_url",
    "sub2api_email",
    "sub2api_concurrency",
    "sub2api_priority",
  ];
  for (const name of textFields) {
    const control = form.elements.namedItem(name);
    if (control) control.value = values[name] ?? "";
  }
  for (const name of ["management_push", "management_overwrite", "sub2api_push"]) {
    const control = form.elements.namedItem(name);
    if (control) control.checked = Boolean(values[name]);
  }
  renderSub2APIGroupOptions(form, values.sub2api_group_id);
  for (const name of ["proxy", "management_api_key", "sub2api_password", "sub2api_api_key", "sub2api_totp_secret"]) {
    const control = form.elements.namedItem(name);
    if (control) control.value = "";
  }
  renderSecretControls(form);
  byId("backup-status").textContent = values.last_backup_path
    ? `最近备份：${values.last_backup_path}${values.last_backup_at ? ` · ${formatDate(values.last_backup_at)}` : ""}`
    : "尚未创建备份";
}

function renderAll() {
  renderWorkspaceTable();
  renderAccountView();
  renderRunTable();
  renderQueue();
  renderSettings();
}

function updateResource(name, payload) {
  state.errors[name] = "";
  if (name === "workspaces") state.workspaces = asList(payload, ["workspaces"]);
  if (name === "accounts") state.accounts = asList(payload, ["accounts"]);
  if (name === "runs") state.runs = asList(payload, ["runs"]);
  if (name === "queue") state.queue = normalizeQueue(payload);
  if (name === "settings") state.settings = safeSettings(payload, state.settings);
  if (name === "sub2apiGroups") state.sub2apiGroups = safeSub2APIGroups(payload);
}

async function loadResource(name, path, {optional = false} = {}) {
  try {
    const payload = await api(path);
    if (name === "migration") {
      applyMigration(payload);
    } else {
      updateResource(name, payload);
    }
    return payload;
  } catch (error) {
    if (optional && error?.status === 404) return null;
    if (isMigrationError(error)) showMigrationBlocked(error.message);
    state.errors[name] = error?.message || String(error);
    return null;
  }
}

async function refreshResources(names) {
  const paths = {
    workspaces: "/api/workspaces",
    accounts: "/api/accounts",
    runs: "/api/runs",
    queue: "/api/queue",
    settings: "/api/settings",
    sub2apiGroups: "/api/sub2api/groups",
  };
  await Promise.all(names.map((name) => loadResource(name, paths[name])));
  renderAll();
}

function applyMigration(payload) {
  if (!payload || typeof payload !== "object") return;
  state.migration = payload;
  const status = safeString(firstValue(payload, ["status", "state"]));
  const blocked = Boolean(firstValue(payload, ["blocked", "cleanup_blocked"], false)) || status === "cleanup_blocked";
  if (blocked) {
    showMigrationBlocked(safeString(firstValue(payload, ["message", "detail"], "迁移清理尚未完成。")), payload);
  } else if (["complete", "completed", "cleanup_complete", "ready"].includes(status)) {
    clearMigrationBlocked();
  }
}

function upsertById(list, item, identifier) {
  if (!item || typeof item !== "object") return list;
  const id = identifier(item);
  if (!id) return list;
  const index = list.findIndex((candidate) => identifier(candidate) === id);
  if (index === -1) return [item, ...list];
  const next = list.slice();
  next[index] = {...next[index], ...item};
  return next;
}

function applySnapshot(payload) {
  const source = payload?.snapshot && typeof payload.snapshot === "object" ? payload.snapshot : payload;
  if (!source || typeof source !== "object") return;
  if (Array.isArray(source.workspaces)) updateResource("workspaces", source.workspaces);
  if (Array.isArray(source.accounts)) updateResource("accounts", source.accounts);
  if (Array.isArray(source.runs)) updateResource("runs", source.runs);
  if (source.queue || Array.isArray(source.queue_items)) updateResource("queue", source.queue || {items: source.queue_items, paused: source.queue_paused});
  if (source.settings) updateResource("settings", source.settings);
  if (source.migration) applyMigration(source.migration);
  renderAll();
}

function appendActiveRunEvent(record) {
  if (!record || typeof record !== "object") return;
  const recordRunId = safeString(firstValue(record, ["run_id"]));
  if (state.activeRunId && recordRunId && recordRunId !== state.activeRunId) return;
  state.activeRunEvents.push(record);
  if (state.activeRunEvents.length > MAX_EVENT_MEMORY) {
    state.activeRunEvents.splice(0, state.activeRunEvents.length - MAX_EVENT_MEMORY);
  }
  if (byId("run-dialog").open) renderRunDetail(state.activeRun, state.activeRunEvents);
}

function invalidateInventoryResults() {
  state.inventoryDirty = true;
  if (state.accountView === "inventory" && state.inventoryQuery.trim()) {
    scheduleInventorySearch({immediate: true});
  }
  for (const [role, combo] of comboboxes) {
    if (byId("workspace-dialog").open && combo.open && combo.query.trim()) {
      scheduleComboboxSearch(role, {immediate: true});
    }
  }
}

function reconcileEvent(eventType, payload, sequence) {
  if (sequence && eventType !== "reset" && sequence <= state.lastEventSequence) return;
  if (sequence) state.lastEventSequence = Math.max(state.lastEventSequence, sequence);

  if (eventType === "reset") {
    applySnapshot(payload);
    return;
  }

  const source = payload && typeof payload === "object" ? payload : {};
  if (source.snapshot) applySnapshot(source.snapshot);
  if (source.workspace) state.workspaces = upsertById(state.workspaces, source.workspace, workspaceId);
  if (source.account) state.accounts = upsertById(state.accounts, source.account, accountId);
  if (source.run) state.runs = upsertById(state.runs, source.run, runId);
  if (source.queue) state.queue = normalizeQueue(source.queue);
  if (source.settings) state.settings = safeSettings(source.settings);
  if (source.migration) applyMigration(source.migration);

  const sourceType = safeString(firstValue(source, ["type", "event_type", "kind"]));
  const inventoryChanged = eventType === "inventory_changed" || sourceType === "inventory_changed";
  if (inventoryChanged) invalidateInventoryResults();

  const record = inventoryChanged ? null : source.record || source.event || (["run_event", "message"].includes(eventType) ? source : null);
  if (record) appendActiveRunEvent(record);
  renderAll();
}

function parseEvent(event, eventType) {
  let payload = {};
  try {
    payload = JSON.parse(event.data || "{}");
  } catch (_) {
    return;
  }
  const sequence = Number(event.lastEventId || firstValue(payload, ["seq", "sequence", "id"], 0));
  reconcileEvent(eventType, payload, Number.isFinite(sequence) ? sequence : 0);
}

function connectEvents() {
  if (state.eventSource) state.eventSource.close();
  const query = new URLSearchParams({token: state.requestToken});
  if (state.lastEventSequence) query.set("after", String(state.lastEventSequence));
  const source = new EventSource(`/api/events?${query.toString()}`);
  state.eventSource = source;
  source.addEventListener("open", () => setConnection("connected", "本地服务已连接"));
  source.addEventListener("error", () => {
    setConnection("recovering", "正在恢复连接…");
    void refreshRequestToken()
      .then(() => {
        if (state.eventSource === source) connectEvents();
      })
      .catch(() => {});
  });
  for (const eventType of ["reset", "run_event", "queue", "workspace", "account", "run", "settings", "migration", "inventory_changed"]) {
    source.addEventListener(eventType, (event) => parseEvent(event, eventType));
  }
  source.addEventListener("message", (event) => parseEvent(event, "message"));
}

function comboboxInput(role) {
  return document.querySelector(`[data-combobox-input="${role}"]`);
}

function comboboxList(role) {
  return byId(`workspace-${role}-options`);
}

function comboboxStatus(role) {
  return byId(`workspace-${role}-status`);
}

function accountChoice(account, detail = "已用账号") {
  return {
    kind: "account",
    id: accountId(account),
    label: accountEmail(account),
    detail,
    status: safeString(firstValue(account, ["status", "state"], "available")),
    disabled: false,
  };
}

function inventoryChoice(item) {
  const aliasNumber = inventoryAliasNumber(item);
  const itemStatus = safeString(firstValue(item, ["status", "state"], "available"));
  return {
    kind: "inventory",
    id: inventoryId(item),
    label: inventoryEmail(item),
    detail: aliasNumber >= 1 && aliasNumber <= 5 ? `库存 · 将分配 +${aliasNumber}` : "库存 · 无可分配子号",
    aliasNumber,
    status: itemStatus,
    disabled: itemStatus !== "available" || aliasNumber < 1 || aliasNumber > 5,
  };
}

function comboboxChoices(role) {
  const combo = comboboxes.get(role);
  const query = combo.query.trim().toLocaleLowerCase("zh-CN");
  const choices = [];
  const seen = new Set();
  const add = (choice) => {
    const key = `${choice.kind}:${choice.id}`;
    if (!choice.id || seen.has(key)) return;
    seen.add(key);
    choices.push(choice);
  };
  if (combo.original) add({...combo.original, detail: "当前绑定"});
  if (combo.selected) add(combo.selected);
  for (const account of state.accounts) {
    const id = accountId(account);
    const status = safeString(firstValue(account, ["status", "state"]));
    const isPinned = combo.original?.id === id || combo.selected?.id === id;
    if (status !== "available" && !isPinned) continue;
    const email = accountEmail(account);
    const haystack = `${email} ${safeString(account.primary_email)}`.toLocaleLowerCase("zh-CN");
    if (query && !haystack.includes(query)) continue;
    add(accountChoice(account));
    if (choices.filter((choice) => choice.kind === "account").length >= 8) break;
  }
  for (const item of combo.inventoryResults.slice(0, INVENTORY_SEARCH_LIMIT)) add(inventoryChoice(item));
  return choices;
}

function syncComboboxHiddenValues(role) {
  const combo = comboboxes.get(role);
  const form = byId("workspace-form");
  form.elements.namedItem(`${role}_account_id`).value = combo.selected?.kind === "account" ? combo.selected.id : "";
  form.elements.namedItem(`${role}_inventory_id`).value = combo.selected?.kind === "inventory" ? combo.selected.id : "";
}

function renderCombobox(role) {
  const combo = comboboxes.get(role);
  const input = comboboxInput(role);
  const list = comboboxList(role);
  const status = comboboxStatus(role);
  const choices = comboboxChoices(role);
  const clearButton = document.querySelector(`[data-action="clear-combobox"][data-role="${role}"]`);
  if (clearButton) clearButton.disabled = !combo.selected && !combo.query;
  syncComboboxHiddenValues(role);
  input.setAttribute("aria-expanded", String(combo.open));
  list.hidden = !combo.open;
  list.replaceChildren();

  if (combo.open) {
    if (!choices.length) {
      const message = combo.loading ? "正在搜索库存…" : combo.error ? combo.error : combo.query.trim() ? "未找到匹配账号或库存" : "没有可用账号，输入邮箱搜索库存";
      list.append(element("li", {className: "empty-state", text: message, attrs: {role: "presentation"}}));
      combo.activeIndex = -1;
    } else {
      combo.activeIndex = Math.min(Math.max(combo.activeIndex, -1), choices.length - 1);
      const fragment = document.createDocumentFragment();
      choices.forEach((choice, index) => {
        const optionId = `workspace-${role}-option-${index}`;
        const option = element("button", {
          className: "combobox-option",
          dataset: {action: "select-combobox-option", role, index},
          attrs: {
            id: optionId,
            type: "button",
            role: "option",
            "aria-selected": String(index === combo.activeIndex),
          },
        }, [
          element("span", {className: "combobox-option__copy"}, [
            element("strong", {text: choice.label}),
            element("small", {text: choice.detail}),
          ]),
          element("span", {className: "combobox-option__kind", text: choice.kind === "account" ? "账号" : "库存"}),
        ]);
        option.disabled = choice.disabled;
        fragment.append(element("li", {attrs: {role: "presentation"}}, [option]));
      });
      list.append(fragment);
    }
  }

  if (combo.activeIndex >= 0 && choices[combo.activeIndex]) {
    input.setAttribute("aria-activedescendant", `workspace-${role}-option-${combo.activeIndex}`);
  } else {
    input.removeAttribute("aria-activedescendant");
  }
  status.dataset.state = combo.error ? "error" : combo.selected ? "selected" : "idle";
  status.textContent = combo.error
    ? combo.error
    : combo.selected
      ? `${combo.selected.kind === "account" ? "已选账号" : "提交时分配"}：${combo.selected.label}${combo.selected.kind === "inventory" ? ` +${combo.selected.aliasNumber}` : ""}`
      : combo.loading
        ? "正在搜索库存…"
        : "可选择已用账号，或输入主邮箱搜索库存";
}

function cancelComboboxSearch(role, {invalidate = true} = {}) {
  const combo = comboboxes.get(role);
  if (combo.searchTimer) window.clearTimeout(combo.searchTimer);
  combo.searchTimer = null;
  combo.requestController?.abort();
  combo.requestController = null;
  combo.loading = false;
  if (invalidate) combo.searchSequence += 1;
}

function scheduleComboboxSearch(role, {immediate = false} = {}) {
  const combo = comboboxes.get(role);
  cancelComboboxSearch(role);
  if (!combo.query.trim()) {
    combo.inventoryResults = [];
    combo.error = "";
    renderCombobox(role);
    return;
  }
  combo.searchTimer = window.setTimeout(() => {
    combo.searchTimer = null;
    searchComboboxInventory(role).catch(() => {});
  }, immediate ? 0 : INVENTORY_SEARCH_DELAY);
}

async function searchComboboxInventory(role) {
  const combo = comboboxes.get(role);
  const query = combo.query.trim();
  if (!query) return;
  const sequence = ++combo.searchSequence;
  const controller = new AbortController();
  combo.requestController = controller;
  combo.loading = true;
  combo.error = "";
  renderCombobox(role);
  const params = new URLSearchParams({query, status: "available", limit: String(INVENTORY_SEARCH_LIMIT)});
  try {
    const payload = await api(`/api/mailbox-inventory?${params.toString()}`, {signal: controller.signal});
    if (sequence !== combo.searchSequence) return;
    combo.inventoryResults = asList(payload, ["inventory", "mailbox_inventory"]).slice(0, INVENTORY_SEARCH_LIMIT);
  } catch (error) {
    if (error?.code === "request_cancelled" || sequence !== combo.searchSequence) return;
    combo.error = error?.message || String(error);
    combo.inventoryResults = [];
  } finally {
    if (sequence === combo.searchSequence) {
      combo.loading = false;
      combo.requestController = null;
      renderCombobox(role);
    }
  }
}

function selectComboboxChoice(role, index) {
  const combo = comboboxes.get(role);
  const choice = comboboxChoices(role)[index];
  if (!choice || choice.disabled) return;
  combo.selected = choice;
  combo.query = choice.label;
  combo.open = false;
  combo.activeIndex = -1;
  comboboxInput(role).value = choice.label;
  cancelComboboxSearch(role);
  renderCombobox(role);
  comboboxInput(role).focus();
}

function clearCombobox(role) {
  const combo = comboboxes.get(role);
  cancelComboboxSearch(role);
  combo.selected = null;
  combo.query = "";
  combo.inventoryResults = [];
  combo.error = "";
  combo.open = true;
  combo.activeIndex = -1;
  const input = comboboxInput(role);
  input.value = "";
  renderCombobox(role);
  input.focus();
}

function moveComboboxActive(role, direction) {
  const combo = comboboxes.get(role);
  const choices = comboboxChoices(role);
  const available = choices.map((choice, index) => choice.disabled ? -1 : index).filter((index) => index >= 0);
  if (!available.length) return;
  const currentPosition = available.indexOf(combo.activeIndex);
  const nextPosition = currentPosition < 0
    ? direction > 0 ? 0 : available.length - 1
    : (currentPosition + direction + available.length) % available.length;
  combo.activeIndex = available[nextPosition];
  combo.open = true;
  renderCombobox(role);
  byId(`workspace-${role}-option-${combo.activeIndex}`)?.scrollIntoView({block: "nearest"});
}

function resetComboboxes() {
  for (const [role, combo] of comboboxes) {
    cancelComboboxSearch(role);
    combo.selected = null;
    combo.original = null;
    combo.query = "";
    combo.inventoryResults = [];
    combo.error = "";
    combo.open = false;
    combo.activeIndex = -1;
    const input = comboboxInput(role);
    if (input) input.value = "";
    if (input) renderCombobox(role);
  }
}

function initializeCombobox(role, accountIdentifier) {
  const combo = comboboxes.get(role);
  cancelComboboxSearch(role);
  const account = findAccount(accountIdentifier);
  const selected = account ? accountChoice(account, "当前绑定") : null;
  combo.selected = selected;
  combo.original = selected;
  combo.query = selected?.label || "";
  combo.inventoryResults = [];
  combo.error = "";
  combo.open = false;
  combo.activeIndex = -1;
  comboboxInput(role).value = combo.query;
  renderCombobox(role);
}

function openWorkspaceDialog(workspace = null) {
  const dialog = byId("workspace-dialog");
  const form = byId("workspace-form");
  byId("workspace-dialog-title").textContent = workspace ? "编辑空间" : "新增空间";
  form.elements.namedItem("workspace_id").value = workspace ? workspaceId(workspace) : "";
  form.elements.namedItem("version").value = workspace ? safeString(firstValue(workspace, ["version"], 1)) : "";
  form.elements.namedItem("name").value = workspace ? workspaceName(workspace) : "";
  const uidControl = form.elements.namedItem("workspace_uid");
  uidControl.value = workspace ? workspaceUid(workspace) : "";
  uidControl.readOnly = Boolean(workspace);
  uidControl.setAttribute("aria-readonly", String(Boolean(workspace)));
  initializeCombobox("current", firstValue(workspace, ["current_account_id"]));
  initializeCombobox("next", firstValue(workspace, ["next_account_id"]));
  byId("workspace-form-error").hidden = true;
  dialog.showModal();
}

function closeDialog(button) {
  const dialog = button.closest("dialog");
  if (dialog) dialog.close();
}

function stageStatesFromRun(run, events) {
  const explicit = run?.stages && typeof run.stages === "object" ? run.stages : {};
  const result = {};
  for (const [step] of STEP_DEFINITIONS) result[step] = safeString(explicit[step], "pending");
  for (const event of events) {
    const step = safeString(firstValue(event, ["step", "stage"]));
    if (!step || !(step in result)) continue;
    const eventState = safeString(firstValue(event, ["state", "status"]));
    if (eventState) result[step] = eventState;
    else if (firstValue(event, ["level"]) === "error") result[step] = "failed";
  }
  const current = safeString(firstValue(run, ["current_step", "step"]));
  const runState = safeString(firstValue(run, ["state", "status"]));
  if (current && result[current] === "pending" && ACTIVE_RUN_STATES.has(runState)) result[current] = "running";
  if (runState === "succeeded") {
    for (const [step] of STEP_DEFINITIONS) if (result[step] === "pending") result[step] = "done";
  }
  return result;
}

function runResultObject(run) {
  const result = run?.result || run?.result_json || {};
  if (result && typeof result === "object") return result;
  try {
    const parsed = JSON.parse(result);
    return parsed && typeof parsed === "object" ? parsed : {};
  } catch (_) {
    return {};
  }
}

function renderRunDetail(run, events = []) {
  const container = byId("run-detail-content");
  container.replaceChildren();
  if (!run) {
    container.append(element("div", {className: "inline-error", text: state.errors.runDetail || "运行详情不可用"}));
    return;
  }

  const id = runId(run);
  const runState = safeString(firstValue(run, ["state", "status"], "queued"));
  const [current, next] = runAccountSnapshot(run);
  byId("run-dialog-title").textContent = runWorkspaceLabel(run);
  const identity = element("div", {className: "run-identity"});
  const identityItems = [
    ["运行状态", statusBadge(runState, RUN_STATUS)],
    ["运行 ID", element("strong", {className: "cell-code", text: shortId(id), attrs: {title: id}})],
    ["当前账号快照", element("strong", {text: current, attrs: {title: current}})],
    ["下一账号快照", element("strong", {text: next, attrs: {title: next}})],
  ];
  for (const [label, value] of identityItems) {
    const item = element("div", {}, [element("span", {text: label}), value]);
    identity.append(item);
  }
  container.append(identity);

  const stageSection = element("section", {className: "stage-section"}, [element("h3", {text: "8 阶段进度"})]);
  const stageList = element("ol", {className: "stage-list"});
  const stageStates = stageStatesFromRun(run, events);
  STEP_DEFINITIONS.forEach(([step, label], index) => {
    const stageState = stageStates[step];
    stageList.append(element("li", {className: "stage-item", dataset: {state: stageState}}, [
      element("span", {className: "stage-index", text: String(index + 1).padStart(2, "0")}),
      element("span", {className: "stage-name", text: label}),
      element("span", {className: "stage-state", text: STEP_STATE_LABELS[stageState] || stageState}),
    ]));
  });
  stageSection.append(stageList);
  container.append(stageSection);

  const redactedError = safeString(firstValue(run, ["redacted_error", "error"]));
  if (redactedError) container.append(element("div", {className: "inline-error", text: redactedError}));

  const important = events.filter((record) => !Boolean(record.routine)).slice(-8).reverse();
  const eventSection = element("section", {className: "event-section"}, [element("h3", {text: "关键事件"})]);
  const eventList = element("ol", {className: "event-list"});
  if (!important.length) {
    eventList.append(element("li", {className: "empty-state", text: "暂无关键事件"}));
  } else {
    for (const record of important) {
      eventList.append(element("li", {dataset: {level: firstValue(record, ["level"], "info")}}, [
        element("time", {text: formatDate(firstValue(record, ["created_at", "timestamp"]))}),
        element("span", {text: safeString(firstValue(record, ["message"], ""))}),
      ]));
    }
  }
  eventSection.append(eventList);
  container.append(eventSection);

  const details = element("details", {className: "diagnostics"});
  details.append(element("summary", {text: `详细诊断 · ${numberFormatter.format(events.length)} 条` }));
  const log = element("div", {className: "diagnostic-log", attrs: {tabindex: "0", "aria-label": "详细诊断日志"}});
  const visibleEvents = events.slice(-MAX_DIAGNOSTIC_ROWS);
  if (!visibleEvents.length) {
    log.append(element("div", {className: "log-line"}, [element("time", {text: "--:--:--"}), element("span", {text: "暂无诊断日志"})]));
  } else {
    for (const record of visibleEvents) {
      log.append(element("div", {className: "log-line", dataset: {level: firstValue(record, ["level"], "info")}}, [
        element("time", {text: formatDate(firstValue(record, ["created_at", "timestamp"]))}),
        element("span", {text: safeString(firstValue(record, ["message"], ""))}),
      ]));
    }
  }
  details.append(log);
  container.append(details);

  const result = runResultObject(run);
  const outputs = [
    ["CPA 文件", firstValue(result, ["cpa_path", "output_path"], firstValue(run, ["cpa_path"]))],
    ["CPA 管理端", firstValue(result, ["management_status", "push_status"], "-")],
    ["Sub2API", firstValue(result, ["sub2api_status"], "-")],
  ];
  const outputSection = element("section", {className: "output-section"}, [element("h3", {text: "输出"})]);
  const outputList = element("dl", {className: "run-output"});
  for (const [label, value] of outputs) {
    outputList.append(element("div", {}, [element("dt", {text: label}), element("dd", {text: safeString(value, "-")})]));
  }
  outputSection.append(outputList);
  container.append(outputSection);

  const footer = byId("run-dialog-footer");
  footer.replaceChildren(actionButton("关闭", "close-dialog", {}, "button"));
  if (ACTIVE_RUN_STATES.has(runState)) {
    footer.append(actionButton("停止运行", "stop-run", {runId: id}, "button button--danger"));
  } else if (runState === "failed") {
    const workspaceIdentifier = safeString(firstValue(run, ["workspace_id"]));
    if (workspaceIdentifier) footer.append(actionButton("重试空间", "retry-workspace", {workspaceId: workspaceIdentifier}, "button button--primary"));
  }
}

async function openRunDetail(id) {
  state.activeRunId = id;
  state.activeRun = null;
  state.activeRunEvents = [];
  byId("run-detail-content").replaceChildren(element("div", {className: "loading-block"}, [
    element("span", {className: "inline-loader", attrs: {"aria-hidden": "true"}}),
    "正在载入运行详情…",
  ]));
  byId("run-dialog").showModal();
  try {
    const payload = await api(`/api/runs/${encodeURIComponent(id)}`);
    const run = payload?.run && typeof payload.run === "object" ? payload.run : payload;
    const events = asList(payload, ["events", "run_events", "logs"]);
    state.activeRun = run;
    state.activeRunEvents = events.slice(-MAX_EVENT_MEMORY);
    renderRunDetail(run, state.activeRunEvents);
  } catch (error) {
    state.errors.runDetail = error?.message || String(error);
    renderRunDetail(null);
  }
}

function fieldError(containerId, message) {
  const container = byId(containerId);
  container.textContent = message;
  container.hidden = !message;
}

async function withBusy(button, task) {
  if (!button) return task();
  const originalDisabled = button.disabled;
  button.disabled = true;
  button.setAttribute("aria-busy", "true");
  try {
    return await task();
  } catch (error) {
    if (isMigrationError(error)) showMigrationBlocked(error.message);
    showToast(error?.message || String(error), "error");
    throw error;
  } finally {
    button.removeAttribute("aria-busy");
    button.disabled = originalDisabled;
  }
}

async function chooseLocalPath(kind, current = "") {
  const payload = await api("/api/dialog", {
    method: "POST",
    body: {kind, current},
  });
  return safeString(firstValue(payload, ["path"]));
}

async function enqueueSelected() {
  if (!ensureMutable()) return;
  const workspaceIds = [...state.selectedWorkspaceIds];
  if (!workspaceIds.length) return;
  await api("/api/queue", {method: "POST", body: {workspace_ids: workspaceIds}});
  state.selectedWorkspaceIds.clear();
  await refreshResources(["workspaces", "runs", "queue"]);
  showToast(`${numberFormatter.format(workspaceIds.length)} 个空间已加入队列`, "success");
}

async function retryWorkspace(id) {
  if (!ensureMutable()) return;
  await api(`/api/workspaces/${encodeURIComponent(id)}/retry`, {method: "POST", body: {}});
  await refreshResources(["workspaces", "runs", "queue"]);
  showToast("重试任务已加入队列", "success");
}

async function updateAccountStatus(id, nextStatus) {
  if (!ensureMutable()) return;
  if (nextStatus === "retired" && !window.confirm("退役后该账号不会再用于空间绑定。确认继续？")) return;
  await api(`/api/accounts/${encodeURIComponent(id)}/status`, {method: "PATCH", body: {status: nextStatus}});
  await refreshResources(["accounts", "workspaces"]);
  showToast("账号状态已更新", "success");
}

async function stopRun(id) {
  if (!ensureMutable()) return;
  if (!window.confirm("确认停止当前运行？已完成的阶段检查点会保留。")) return;
  await api(`/api/runs/${encodeURIComponent(id)}/stop`, {method: "POST", body: {}});
  await refreshResources(["workspaces", "runs", "queue"]);
  showToast("已请求停止运行", "success");
}

async function moveQueueItem(id, direction) {
  if (!ensureMutable()) return;
  const items = activeQueueItems();
  const index = items.findIndex((item) => safeString(firstValue(item, ["id", "queue_item_id"])) === id);
  const target = direction === "up" ? index - 1 : index + 1;
  if (index < 0 || target < 0 || target >= items.length) return;
  [items[index], items[target]] = [items[target], items[index]];
  const itemIds = items.map((item) => safeString(firstValue(item, ["id", "queue_item_id"])));
  await api("/api/queue/order", {method: "PATCH", body: {queue_item_ids: itemIds}});
  await refreshResources(["queue"]);
}

async function toggleQueuePause() {
  if (!ensureMutable()) return;
  const paused = !state.queue.paused;
  await api("/api/queue/pause", {method: "POST", body: {paused}});
  await refreshResources(["queue"]);
  showToast(paused ? "队列已暂停" : "队列已继续", "success");
}

async function retryMigrationCleanup() {
  let payload;
  try {
    payload = await api("/api/migration/cleanup", {method: "POST", body: {}});
  } catch (error) {
    if (error?.status !== 404) throw error;
    payload = await api("/api/migration/cleanup/retry", {method: "POST", body: {}});
  }
  applyMigration(payload);
  if (!state.migrationBlocked) {
    await refreshResources(["workspaces", "accounts", "runs", "queue", "settings"]);
    showToast("迁移清理已完成", "success");
  }
}

async function createBackup() {
  if (!ensureMutable()) return;
  const payload = await api("/api/backups", {method: "POST", body: {}});
  const path = safeString(firstValue(payload, ["path", "backup_path"]), "备份已创建");
  byId("backup-status").textContent = `最近备份：${path}`;
  showToast("加密备份已创建", "success");
}

async function restoreBackup() {
  if (!ensureMutable()) return;
  const path = await chooseLocalPath("backup", "");
  if (!path) return;
  if (!window.confirm("恢复会替换当前本地数据库，且队列必须已暂停。确认继续？")) return;
  await api("/api/backups/restore", {method: "POST", body: {path}});
  await refreshResources(["workspaces", "accounts", "runs", "queue", "settings"]);
  renderSettings({force: true});
  showToast("备份恢复完成", "success");
}

async function handleWorkspaceSubmit(form) {
  if (!ensureMutable()) return;
  fieldError("workspace-form-error", "");
  const values = Object.fromEntries(new FormData(form).entries());
  if (!safeString(values.name).trim() || !safeString(values.workspace_uid).trim()) {
    fieldError("workspace-form-error", "空间名称和 Workspace ID 不能为空");
    const firstInvalid = !safeString(values.name).trim() ? form.elements.namedItem("name") : form.elements.namedItem("workspace_uid");
    firstInvalid.focus();
    return;
  }
  const current = comboboxes.get("current").selected;
  const next = comboboxes.get("next").selected;
  if (!current || !next) {
    fieldError("workspace-form-error", "请明确选择当前账号和下一账号");
    comboboxInput(!current ? "current" : "next").focus();
    return;
  }
  if (current.kind === "account" && next.kind === "account" && current.id === next.id) {
    fieldError("workspace-form-error", "当前账号和下一账号不能相同");
    return;
  }
  const payload = {
    name: safeString(values.name).trim(),
  };
  if (current.kind === "account") payload.current_account_id = current.id;
  else payload.current_inventory_id = current.id;
  if (next.kind === "account") payload.next_account_id = next.id;
  else payload.next_inventory_id = next.id;
  const id = safeString(values.workspace_id);
  if (id) {
    payload.version = Number(values.version || 1);
    await api(`/api/workspaces/${encodeURIComponent(id)}`, {method: "PATCH", body: payload});
  } else {
    payload.workspace_uid = safeString(values.workspace_uid).trim();
    await api("/api/workspaces", {method: "POST", body: payload});
  }
  byId("workspace-dialog").close();
  await refreshResources(["workspaces", "accounts"]);
  showToast(id ? "空间已更新" : "空间已添加", "success");
}

async function handleAccountImport(form) {
  if (!ensureMutable()) return;
  fieldError("account-import-error", "");
  const path = safeString(new FormData(form).get("path")).trim();
  if (!path) {
    fieldError("account-import-error", "请选择 Outlook / Hotmail TXT 文件");
    return;
  }
  const payload = await api("/api/accounts/import", {method: "POST", body: {path}});
  byId("account-import-dialog").close();
  form.reset();
  const imported = Number(firstValue(payload, ["imported", "created"], 0));
  const existing = Number(firstValue(payload, ["existing", "unchanged"], 0));
  const invalid = Number(firstValue(payload, ["invalid", "rejected"], 0));
  state.inventoryDirty = true;
  if (state.accountView === "inventory" && state.inventoryQuery.trim()) scheduleInventorySearch({immediate: true});
  showToast(`库存导入完成：新增 ${numberFormatter.format(imported)}，已存在 ${numberFormatter.format(existing)}，无效 ${numberFormatter.format(invalid)}`, "success");
}

function openInventoryAllocation(item) {
  if (!item) return;
  const dialog = byId("account-allocation-dialog");
  const form = byId("account-allocation-form");
  form.elements.namedItem("inventory_id").value = inventoryId(item);
  byId("allocation-primary-email").textContent = inventoryEmail(item);
  byId("allocation-next-alias").textContent = inventoryAliasEmail(item);
  fieldError("account-allocation-error", "");
  dialog.showModal();
}

async function handleInventoryAllocation(form) {
  if (!ensureMutable()) return;
  fieldError("account-allocation-error", "");
  const inventoryIdentifier = safeString(new FormData(form).get("inventory_id"));
  if (!inventoryIdentifier) {
    fieldError("account-allocation-error", "库存记录已失效，请重新搜索");
    return;
  }
  const account = await api(`/api/mailbox-inventory/${encodeURIComponent(inventoryIdentifier)}/allocate`, {method: "POST", body: {}});
  byId("account-allocation-dialog").close();
  await refreshResources(["accounts"]);
  state.inventoryDirty = true;
  if (state.inventoryQuery.trim()) scheduleInventorySearch({immediate: true});
  showToast(`已分配 ${accountEmail(account)}`, "success");
}

async function invalidateBoundAccount(id, failureType) {
  if (!ensureMutable()) return;
  const account = findAccount(id);
  const binding = account && accountBinding(account);
  if (!account || !binding?.workspace || !binding.role) {
    throw new ApiError("账号绑定已变化，请刷新后重试", {code: "binding_changed"});
  }
  const workspace = binding.workspace;
  const role = binding.role;
  const current = workspaceAccountLabel(workspace, "current");
  const next = workspaceAccountLabel(workspace, "next");
  const effect = role === "current"
    ? `${next === "未分配" ? "当前没有可提升的下一账号" : `${next} 将提升为当前账号`}，系统将尝试补充下一账号。`
    : `${current} 保持当前账号，系统将替换下一账号。`;
  const scope = failureType === "mailbox_credentials_invalid"
    ? `主邮箱 ${safeString(account.primary_email, accountEmail(account))} 将被禁用，未分配子号不再使用。`
    : `${accountEmail(account)} 将标记为不可用。`;
  if (!window.confirm(`${scope}\n\n${effect}\n\n确认继续？`)) return;
  await api(`/api/workspaces/${encodeURIComponent(workspaceId(workspace))}/replace-account`, {
    method: "POST",
    body: {
      role,
      failure_code: failureType,
      version: Number(firstValue(workspace, ["version"], 1)),
    },
  });
  state.inventoryDirty = true;
  await refreshResources(["workspaces", "accounts", "runs", "queue"]);
  if (state.accountView === "inventory" && state.inventoryQuery.trim()) scheduleInventorySearch({immediate: true});
  showToast("账号失效处理已完成", "success");
}

async function advanceWorkspace(id) {
  if (!ensureMutable()) return;
  const workspace = findWorkspace(id);
  if (!workspace) throw new ApiError("空间状态已变化，请刷新后重试", {code: "workspace_changed"});
  const current = workspaceAccountLabel(workspace, "current");
  const next = workspaceAccountLabel(workspace, "next");
  if (next === "未分配") {
    throw new ApiError("当前空间没有可提升的下一账号", {code: "next_account_missing"});
  }
  if (!window.confirm(
    `确认已将 ${next} 切换为当前账号？\n\n${current} 将归档，系统会自动分配新的下一账号。`
  )) return;
  const result = await api(`/api/workspaces/${encodeURIComponent(id)}/advance`, {
    method: "POST",
    body: {version: Number(firstValue(workspace, ["version"], 1))},
  });
  state.inventoryDirty = true;
  await refreshResources(["workspaces", "accounts", "runs", "queue"]);
  if (state.accountView === "inventory" && state.inventoryQuery.trim()) {
    scheduleInventorySearch({immediate: true});
  }
  const replacement = result?.replacement ? accountEmail(result.replacement) : "未分配";
  showToast(`轮换已确认，新的下一账号：${replacement}`, "success");
}

function settingsPayload(form) {
  const data = new FormData(form);
  const values = {
    output_dir: safeString(data.get("output_dir")).trim(),
    pat_name: safeString(data.get("pat_name")).trim(),
    management_base_url: safeString(data.get("management_url")).trim(),
    management_remote_name: safeString(data.get("management_filename")).trim(),
    management_push: data.get("management_push") === "on",
    management_replace: data.get("management_overwrite") === "on",
    sub2api_base_url: safeString(data.get("sub2api_url")).trim(),
    sub2api_email: safeString(data.get("sub2api_email")).trim(),
    sub2api_push: data.get("sub2api_push") === "on",
  };
  for (const name of ["pat_ttl", "invite_settle_seconds", "sub2api_concurrency", "sub2api_priority"]) {
    const raw = safeString(data.get(name)).trim();
    if (raw) values[name] = Number(raw);
  }
  const sub2apiGroupId = safeString(data.get("sub2api_group_id")).trim();
  values.sub2api_group_id = sub2apiGroupId ? Number(sub2apiGroupId) : "";
  const secrets = {};
  for (const secretName of ["proxy", "management_api_key", "sub2api_password", "sub2api_api_key", "sub2api_totp_secret"]) {
    const value = safeString(data.get(secretName));
    if (value && !state.clearSecrets.has(secretName)) secrets[secretName] = value;
  }
  return {values, secrets, clear_secrets: [...state.clearSecrets]};
}

async function handleSettingsSubmit(form) {
  if (!ensureMutable()) return;
  const invalid = form.querySelector(":invalid");
  if (invalid) {
    invalid.focus();
    throw new ApiError("请修正格式或范围不正确的设置项", {code: "invalid_settings"});
  }
  const payload = settingsPayload(form);
  if (payload.values.pat_ttl && payload.values.pat_ttl < 60) {
    const field = form.elements.namedItem("pat_ttl");
    field.focus();
    throw new ApiError("PAT TTL 不能小于 60 秒", {code: "invalid_pat_ttl"});
  }
  const response = await api("/api/settings", {method: "PUT", body: payload});
  state.settings = safeSettings(response || {values: payload.values, secrets: state.settings});
  state.settingsDirty = false;
  state.clearSecrets.clear();
  renderSettings({force: true});
  byId("settings-save-state").textContent = `已保存 · ${formatDate(new Date().toISOString())}`;
  showToast("设置已保存", "success");
  void loadResource("sub2apiGroups", "/api/sub2api/groups").then(() => {
    renderSettings();
  });
}

document.addEventListener("click", (event) => {
  const button = event.target.closest("[data-action]");
  if (!event.target.closest(".account-combobox")) {
    for (const [role, combo] of comboboxes) {
      if (combo.open) {
        combo.open = false;
        combo.activeIndex = -1;
        renderCombobox(role);
      }
    }
  }
  if (!button) return;
  const action = button.dataset.action;
  const run = async () => {
    if (action === "toggle-queue") {
      state.queueExpanded = !state.queueExpanded;
      renderQueue();
      return;
    }
    if (action === "close-dialog") return closeDialog(button);
    if (action === "open-workspace-dialog") return openWorkspaceDialog();
    if (action === "edit-workspace") return openWorkspaceDialog(findWorkspace(button.dataset.workspaceId));
    if (action === "advance-workspace") return advanceWorkspace(button.dataset.workspaceId);
    if (action === "open-account-import") {
      fieldError("account-import-error", "");
      byId("account-import-dialog").showModal();
      return;
    }
    if (action === "select-account-view") return selectAccountView(button.dataset.accountView);
    if (action === "open-inventory-allocation") {
      return openInventoryAllocation(state.inventoryResults.find((item) => inventoryId(item) === button.dataset.inventoryId));
    }
    if (action === "invalidate-bound-account") return invalidateBoundAccount(button.dataset.accountId, button.dataset.failureType);
    if (action === "clear-combobox") return clearCombobox(button.dataset.role);
    if (action === "select-combobox-option") return selectComboboxChoice(button.dataset.role, Number(button.dataset.index));
    if (action === "choose-account-file") {
      const input = byId("account-import-form").elements.namedItem("path");
      input.value = await chooseLocalPath("txt", input.value);
      return;
    }
    if (action === "choose-output-directory") {
      const input = byId("settings-form").elements.namedItem("output_dir");
      const selected = await chooseLocalPath("directory", input.value);
      if (selected) {
        input.value = selected;
        state.settingsDirty = true;
      }
      return;
    }
    if (action === "enqueue-selected") return enqueueSelected();
    if (action === "retry-workspace") return retryWorkspace(button.dataset.workspaceId);
    if (action === "open-run-detail") return openRunDetail(button.dataset.runId);
    if (action === "set-account-status") return updateAccountStatus(button.dataset.accountId, button.dataset.status);
    if (action === "account-page-prev") return changeAccountPage(-1);
    if (action === "account-page-next") return changeAccountPage(1);
    if (action === "stop-run") return stopRun(button.dataset.runId);
    if (action === "move-queue-item") return moveQueueItem(button.dataset.queueItemId, button.dataset.direction);
    if (action === "toggle-queue-pause") return toggleQueuePause();
    if (action === "retry-migration-cleanup") return retryMigrationCleanup();
    if (action === "create-backup") return createBackup();
    if (action === "restore-backup") return restoreBackup();
    if (action === "toggle-secret-clear") {
      const secret = button.dataset.secret;
      if (state.clearSecrets.has(secret)) state.clearSecrets.delete(secret);
      else state.clearSecrets.add(secret);
      state.settingsDirty = true;
      renderSecretControls();
      return;
    }
    if (action === "filter-workspaces") {
      state.filters.workspaceStatus = button.dataset.status;
      for (const candidate of byId("workspace-status-filter").querySelectorAll("button")) {
        const active = candidate === button;
        candidate.classList.toggle("is-active", active);
        candidate.setAttribute("aria-pressed", String(active));
      }
      renderWorkspaceTable();
    }
  };
  withBusy(button, run).catch(() => {});
});

document.addEventListener("input", (event) => {
  const target = event.target;
  if (target.id === "workspace-search") {
    state.filters.workspaceSearch = target.value;
    renderWorkspaceTable();
  } else if (target.id === "account-search") {
    state.filters.accountSearch = target.value;
    state.accountPage = 1;
    renderAccountTable();
  } else if (target.id === "inventory-search") {
    state.inventoryQuery = target.value;
    state.inventoryError = "";
    scheduleInventorySearch();
  } else if (target.matches("[data-combobox-input]")) {
    const role = target.dataset.comboboxInput;
    const combo = comboboxes.get(role);
    combo.query = target.value;
    if (combo.selected && target.value !== combo.selected.label) combo.selected = null;
    combo.open = true;
    combo.activeIndex = -1;
    combo.error = "";
    scheduleComboboxSearch(role);
    renderCombobox(role);
  } else if (target.id === "run-search") {
    state.filters.runSearch = target.value;
    renderRunTable();
  } else if (target.closest("#settings-form")) {
    if (["proxy", "management_api_key", "sub2api_password", "sub2api_api_key", "sub2api_totp_secret"].includes(target.name) && target.value) {
      state.clearSecrets.delete(target.name);
    }
    state.settingsDirty = true;
  }
});

document.addEventListener("change", (event) => {
  const target = event.target;
  if (target.matches("[data-workspace-select]")) {
    const id = target.dataset.workspaceSelect;
    if (target.checked) state.selectedWorkspaceIds.add(id);
    else state.selectedWorkspaceIds.delete(id);
    renderWorkspaceTable();
  } else if (target.id === "select-all-workspaces") {
    const readyIds = filteredWorkspaces()
      .filter((workspace) => safeString(firstValue(workspace, ["status", "state"])) === "ready")
      .map(workspaceId);
    for (const id of readyIds) {
      if (target.checked) state.selectedWorkspaceIds.add(id);
      else state.selectedWorkspaceIds.delete(id);
    }
    renderWorkspaceTable();
  } else if (target.id === "account-status-filter") {
    state.filters.accountStatus = target.value;
    state.accountPage = 1;
    renderAccountTable();
  } else if (target.id === "inventory-status-filter") {
    state.inventoryStatus = target.value;
    state.inventoryResults = [];
    state.inventoryError = "";
    scheduleInventorySearch();
  } else if (target.id === "run-state-filter") {
    state.filters.runState = target.value;
    renderRunTable();
  } else if (target.id === "run-date-from") {
    state.filters.runDateFrom = target.value;
    renderRunTable();
  } else if (target.closest("#settings-form")) {
    state.settingsDirty = true;
  }
});

document.addEventListener("submit", (event) => {
  const form = event.target;
  if (!(form instanceof HTMLFormElement)) return;
  event.preventDefault();
  const submitter = event.submitter;
  let task = null;
  if (form.id === "workspace-form") task = () => handleWorkspaceSubmit(form);
  if (form.id === "account-import-form") task = () => handleAccountImport(form);
  if (form.id === "account-allocation-form") task = () => handleInventoryAllocation(form);
  if (form.id === "settings-form") task = () => handleSettingsSubmit(form);
  if (task) withBusy(submitter, task).catch(() => {});
});

for (const dialog of document.querySelectorAll("dialog")) {
  dialog.addEventListener("click", (event) => {
    if (event.target === dialog) dialog.close();
  });
  dialog.addEventListener("close", () => {
    if (dialog.id === "workspace-dialog") resetComboboxes();
  });
}

document.addEventListener("focusin", (event) => {
  const input = event.target.closest?.("[data-combobox-input]");
  if (!input) return;
  const combo = comboboxes.get(input.dataset.comboboxInput);
  combo.open = true;
  renderCombobox(combo.role);
});

document.addEventListener("keydown", (event) => {
  const input = event.target.closest?.("[data-combobox-input]");
  if (input) {
    const role = input.dataset.comboboxInput;
    const combo = comboboxes.get(role);
    if (event.key === "ArrowDown" || event.key === "ArrowUp") {
      event.preventDefault();
      moveComboboxActive(role, event.key === "ArrowDown" ? 1 : -1);
    } else if (event.key === "Enter" && combo.open && combo.activeIndex >= 0) {
      event.preventDefault();
      selectComboboxChoice(role, combo.activeIndex);
    } else if (event.key === "Escape") {
      event.preventDefault();
      cancelComboboxSearch(role);
      combo.open = false;
      combo.activeIndex = -1;
      renderCombobox(role);
      input.focus();
    } else if (event.key === "Tab") {
      combo.open = false;
      combo.activeIndex = -1;
      renderCombobox(role);
    }
    return;
  }
  const tab = event.target.closest?.("[role='tab'][data-account-view]");
  if (tab && ["ArrowLeft", "ArrowRight"].includes(event.key)) {
    event.preventDefault();
    const nextView = tab.dataset.accountView === "used" ? "inventory" : "used";
    selectAccountView(nextView);
    document.querySelector(`[data-account-view="${nextView}"]`).focus();
  }
});

window.addEventListener("hashchange", () => selectView(currentViewFromHash()));
window.addEventListener("beforeunload", (event) => {
  state.eventSource?.close();
  if (state.settingsDirty) {
    event.preventDefault();
    event.returnValue = "";
  }
});

async function bootstrap() {
  selectView(currentViewFromHash());
  if (!window.location.hash) history.replaceState(null, "", "#spaces");
  setConnection("connecting", "正在连接…");
  try {
    const response = await fetch("/api/bootstrap", {cache: "no-store", credentials: "same-origin"});
    const payload = await response.json();
    if (!response.ok) throw normalizedError(payload, response.status);
    state.requestToken = safeString(firstValue(payload, ["request_token", "csrf_token", "token"]));
    if (!state.requestToken) throw new ApiError("本地服务未返回请求令牌", {code: "missing_request_token"});
    if (payload.migration) applyMigration(payload.migration);
    if (payload.snapshot) applySnapshot(payload.snapshot);

    await Promise.all([
      loadResource("workspaces", "/api/workspaces"),
      loadResource("accounts", "/api/accounts"),
      loadResource("runs", "/api/runs"),
      loadResource("queue", "/api/queue"),
      loadResource("settings", "/api/settings"),
      loadResource("sub2apiGroups", "/api/sub2api/groups"),
      loadResource("migration", "/api/migration/status", {optional: true}),
    ]);
    renderAll();
    renderSettings({force: true});
    connectEvents();
  } catch (error) {
    setConnection("disconnected", "连接失败");
    if (isMigrationError(error)) showMigrationBlocked(error.message);
    for (const name of ["workspaces", "accounts", "runs", "queue"]) state.errors[name] = error?.message || String(error);
    renderAll();
    showToast(`${error?.message || String(error)}。请确认本地服务正在运行。`, "error");
  }
}

bootstrap();
