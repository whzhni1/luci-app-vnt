module("luci.controller.vnt", package.seeall)

local sys, http, nixio = require "luci.sys", require "luci.http", require "nixio"

local function json(d) http.prepare_content("application/json") http.write_json(d) end
local function exec(c) return sys.exec(c .. " 2>/dev/null"):gsub("%s+$", "") end
local function read(p) local f = io.open(p, "r") if not f then return end local c = f:read("*all") f:close() return c end

local function runtime(f)
    local c = read(f) if not c then return "-" end
    local s = tonumber(c) if not s then return "-" end
    local d = os.time() - s
    local D, H, M = math.floor(d/86400), math.floor(d%86400/3600), math.floor(d%3600/60)
    return D > 0 and string.format("%d天%02d时%02d分", D, H, M) or string.format("%02d时%02d分%02d秒", H, M, d%60)
end

local function proc(n)
    if sys.call("pgrep " .. n .. " >/dev/null") ~= 0 then return false, "-", "-" end
    local p = exec("pidof " .. n .. " | awk '{print $1}'")
    if p == "" then return true, "0%", "-" end
    local cpu = exec("top -b -n1 | awk '$1==" .. p .. "{print $7}'")
    local ram = exec("cat /proc/" .. p .. "/status | awk '/VmRSS/{printf \"%.1fMB\", $2/1024}'")
    return true, cpu ~= "" and cpu or "0%", ram ~= "" and ram or "-"
end

local function parse_list(v)
    local t = {}
    if v and v ~= "" then for i in v:gmatch("[^|]+") do i = i:match("^%s*(.-)%s*$") if i ~= "" then t[#t+1] = i end end end
    return t
end

local function save_cfg(typ, singles, lists, extra)
    local uci = require "luci.model.uci".cursor()
    local sec = uci:get_first("vnt", typ)
    if not sec then return json({status = "error"}) end
    for _, n in ipairs(singles) do local v = http.formvalue(n) if v then uci:set("vnt", sec, n, v) end end
    for _, n in ipairs(lists or {}) do
        local items = parse_list(http.formvalue(n))
        if #items > 0 then uci:set_list("vnt", sec, n, items) else uci:delete("vnt", sec, n) end
    end
    if extra then extra(uci, sec) end
    uci:commit("vnt")
    os.execute("/etc/init.d/vnt restart >/dev/null 2>&1 &")
    json({status = "ok"})
end

local function build_table(cmd, hdrs, row_fn, empty)
    local d = exec(cmd)
    if d == "" or d:match("[Ee]rror") then return json({html = "<div class='empty'>" .. (empty or "程序未运行") .. "</div>"}) end
    local h = "<table class='dtable'><tr>"
    for _, hdr in ipairs(hdrs) do h = h .. "<th>" .. hdr .. "</th>" end
    h = h .. "</tr>"
    local first = true
    for l in d:gmatch("[^\r\n]+") do
        if first then first = false else
            local cols = {} for c in l:gmatch("%S+") do cols[#cols+1] = c end
            local row = row_fn(cols) if row then h = h .. row end
        end
    end
    json({html = h .. "</table>"})
end

local function log_op(op, t)
    local base = t == "s" and "/tmp/vnts" or "/tmp/vnt-cli"
    if op == "g" then http.write(read(base .. ".log") or "暂无日志")
    else os.execute("rm -f " .. base .. "*.log") json({status = "ok"}) end
end

function index()
    if not nixio.fs.access("/etc/config/vnt") then return end
    entry({"admin", "vpn", "vnt"}, template("vnt/vnt_main"), _("VNT"), 44)
    local R = {"popup_client", "popup_server", "status", "restart", "get_log", "get_log2", "clear_log", "clear_log2",
        "get_config", "save_client", "save_server", "get_ifaces", "get_keys", "vnt_info", "vnt_list", "vnt_route", "vnt_cmd", "get_update", "do_install"}
    for _, r in ipairs(R) do entry({"admin", "vpn", "vnt", r}, r:match("^popup_") and template("vnt/" .. r) or call(r)).leaf = true end
end

function status()
    local uci = require "luci.model.uci".cursor()
    local e = {}
    e.crunning, e.vntcpu, e.vntram = proc("vnt-cli")
    e.srunning, e.vntscpu, e.vntsram = proc("vnts")
    e.vntsta, e.vntsta2 = runtime("/tmp/vnt_time"), runtime("/tmp/vnts_time")
    e.web = tonumber(uci:get_first("vnt", "vnts", "web")) or 0
    e.port = tonumber(uci:get_first("vnt", "vnts", "web_port")) or 29870
    local token = uci:get_first("vnt", "vnt-cli", "token")
    e.token_set = (token and token ~= "") and 1 or 0
    local white = uci:get_first("vnt", "vnts", "white_Token")
    e.white_set = (white and ((type(white)=="table" and #white>0) or (type(white)=="string" and white~=""))) and 1 or 0
    e.mode = uci:get_first("vnt", "vnt-cli", "mode") or "dhcp"
    e.ipaddr = uci:get_first("vnt", "vnt-cli", "ipaddr") or ""
    e.vntshost = uci:get_first("vnt", "vnt-cli", "vntshost") or ""
    e.server_port = uci:get_first("vnt", "vnts", "server_port") or "29872"
    e.subnet = uci:get_first("vnt", "vnts", "subnet") or "10.26.0.1"
    e.netmask = uci:get_first("vnt", "vnts", "servern_netmask") or "255.255.255.0"
    e.vnttag = exec("$(uci -q get vnt.@vnt-cli[0].clibin) -h | grep 'version:' | awk -F':' '{print $2}'")
    e.vntstag = exec("$(uci -q get vnt.@vnts[0].vntsbin) -V | awk '/^version:/{print $2}'")
    json(e)
end

function get_config()
    local uci, e = require "luci.model.uci".cursor(), {}
    for _, c in ipairs({{"vnt-cli", "c_"}, {"vnts", "s_"}}) do
        local s = uci:get_first("vnt", c[1])
        if s then for k, v in pairs(uci:get_all("vnt", s)) do e[c[2]..k] = v end end
    end
    json(e)
end

function get_keys()
    json({public_key = read("/tmp/vnts_key/public_key.pem") or "", private_key = read("/tmp/vnts_key/private_key.pem") or ""})
end

function save_client()
    save_cfg("vnt-cli",
        {"enabled", "token", "mode", "ipaddr", "desvice_id", "desvice_name", "forward", "allow_wg", "log", "clibin",
         "vntshost", "tunname", "relay", "punch", "passmode", "key", "client_port", "mtu", "local_dev", "serverw",
         "finger", "first_latency", "disable_stats", "check", "checktime", "comp"},
        {"localadd", "peeradd", "vntdns", "stunhost", "mapping", "checkip", "vnt_forward"})
end

function save_server()
    save_cfg("vnts", {"enabled", "server_port", "subnet", "servern_netmask", "web", "web_port", "webuser", "webpass", "web_wan", "logs", "vntsbin", "sfinger"}, nil,
        function(uci, sec)
            uci:delete("vnt", sec, "white_Token")
            local vals = http.formvaluetable("white_Token")
            if vals then for _, v in pairs(vals) do if v and v ~= "" then uci:add_list("vnt", sec, "white_Token", v) end end end
            for _, k in ipairs({{"public_key", "public_key.pem"}, {"private_key", "private_key.pem"}}) do
                local v = http.formvalue(k[1])
                if v and v ~= "" then nixio.fs.mkdir("/tmp/vnts_key") nixio.fs.writefile("/tmp/vnts_key/" .. k[2], v:gsub("\r\n", "\n")) end
            end
        end)
end

function get_ifaces()
    local r = {}
    for iface in exec("ls /sys/class/net"):gmatch("%S+") do
        local ip = exec("ip -4 addr show " .. iface .. " | awk '/inet /{print $2}' | cut -d'/' -f1")
        if ip ~= "" then r[#r+1] = {name = iface, ip = ip} end
    end
    json(r)
end

function restart() sys.call("/etc/init.d/vnt restart >/dev/null 2>&1 &") json({status = "ok"}) end
function get_log() log_op("g", "c") end
function get_log2() log_op("g", "s") end
function clear_log() log_op("c", "c") end
function clear_log2() log_op("c", "s") end

function vnt_info()
    local info = exec("$(uci -q get vnt.@vnt-cli[0].clibin) --info")
    if info == "" then info = "错误：程序未运行" end
    for en, cn in pairs({["Connection status"]="连接状态", ["Virtual ip"]="虚拟IP", ["Virtual gateway"]="虚拟网关",
        ["Virtual netmask"]="虚拟掩码", ["NAT type"]="NAT类型", ["Relay server"]="服务器", ["Public ips"]="外网IP", ["Local addr"]="本地地址"}) do
        info = info:gsub(en, cn)
    end
    json({html = "<pre>" .. info .. "</pre>"})
end

function vnt_list()
    build_table("$(uci -q get vnt.@vnt-cli[0].clibin) --all", {"名称", "虚拟IP", "状态", "模式", "延迟", "NAT", "公网IP"},
        function(c)
            if #c < 3 then return nil end
            if c[3]:lower() == "online" and #c >= 7 then
                local rt = tonumber(c[5]) or 0
                return string.format("<tr><td><b>%s</b></td><td><code>%s</code></td><td class='on'>● 在线</td><td>%s</td><td class='%s'>%sms</td><td>%s</td><td>%s</td></tr>",
                    c[1], c[2], c[4]:upper(), rt < 50 and "on" or (rt < 100 and "warn" or "off"), c[5], c[6], c[7])
            end
            return string.format("<tr><td><b>%s</b></td><td><code>%s</code></td><td class='off'>● 离线</td><td>-</td><td>-</td><td>-</td><td>-</td></tr>", c[1], c[2])
        end, "程序未运行或暂无设备")
end

function vnt_route()
    build_table("$(uci -q get vnt.@vnt-cli[0].clibin) --route", {"目标", "下一跳", "跃点", "延迟", "接口"},
        function(c) return #c >= 5 and string.format("<tr><td>%s</td><td>%s</td><td>%s</td><td>%sms</td><td>%s</td></tr>", c[1], c[2], c[3], c[4], c[5]) or nil end)
end

function vnt_cmd()
    local cmd = exec("cat /proc/$(pidof vnt-cli | awk '{print $1}')/cmdline | tr '\\0' ' '")
    json({html = "<pre>" .. (cmd ~= "" and cmd or "程序未运行") .. "</pre>"})
end

local API_BASE = "https://gitlab.com/api/v4/projects/whzhni%2F"

local function pkg_info()
    if sys.call("command -v opkg >/dev/null 2>&1") == 0 then return "opkg", "ipk", exec("opkg print-architecture | awk '!/all|noarch/{a=$2}END{print a}'") end
    if sys.call("command -v apk >/dev/null 2>&1") == 0 then return "apk", "apk", exec("apk --print-arch") end
    return "unknown", "ipk", ""
end

local function fetch_api(api)
    local d = exec("wget -qO- --timeout=5 '" .. API_BASE .. api .. "/releases' 2>/dev/null")
    return (d ~= "") and d or nil
end

function get_update()
    local mgr, ext, arch = pkg_info()
    local api = (http.formvalue("type") or "vnt") == "server" and "vnts" or "vnt"
    local data = fetch_api(api)
    if not data then return json({version = "-", mgr = mgr, arch = arch, files = {}, api_name = api}) end
    local files = {} for f in data:gmatch('"([^"]+%.' .. ext .. ')"') do if not f:match("/") then files[#files+1] = f end end
    json({version = data:match('"tag_name":"v([^"]+)"') or "-", mgr = mgr, arch = arch, files = files, api_name = api})
end

function do_install()
    local file, api = http.formvalue("file"), http.formvalue("api") or "vnt"
    if not file or file == "" then return json({status = "error", msg = "未指定文件"}) end
    local data = fetch_api(api)
    if not data then return json({status = "error", msg = "获取版本失败"}) end
    local url = data:match('(https://[^"]*/' .. file:gsub("([%.%-%+])", "%%%1") .. ')')
    if not url then return json({status = "error", msg = "未找到链接"}) end
    if sys.call("wget -q --timeout=60 '" .. url .. "' -O '/tmp/" .. file .. "'") ~= 0 then return json({status = "error", msg = "下载失败"}) end
    local cmd = sys.call("command -v opkg >/dev/null 2>&1") == 0 and "opkg install" or "apk add --allow-untrusted"
    local r = sys.exec(cmd .. " '/tmp/" .. file .. "' 2>&1")
    sys.call("rm -f '/tmp/" .. file .. "' /tmp/luci-indexcache 2>/dev/null")
    json({status = "ok", msg = r})
end
