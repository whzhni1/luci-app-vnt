module("luci.controller.vnt", package.seeall)

function index()
	if not nixio.fs.access("/etc/config/vnt") then return end
	
	entry({"admin", "vpn", "vnt"}, template("vnt/vnt_main"), _("VNT"), 44)
	entry({"admin", "vpn", "vnt", "popup_client"}, template("vnt/popup_client")).leaf = true
	entry({"admin", "vpn", "vnt", "popup_server"}, template("vnt/popup_server")).leaf = true
	entry({"admin", "vpn", "vnt", "status"}, call("act_status")).leaf = true
	entry({"admin", "vpn", "vnt", "restart"}, call("do_restart")).leaf = true
	entry({"admin", "vpn", "vnt", "get_log"}, call("get_log")).leaf = true
	entry({"admin", "vpn", "vnt", "get_log2"}, call("get_log2")).leaf = true
	entry({"admin", "vpn", "vnt", "clear_log"}, call("clear_log")).leaf = true
	entry({"admin", "vpn", "vnt", "clear_log2"}, call("clear_log2")).leaf = true
	entry({"admin", "vpn", "vnt", "get_config"}, call("get_config")).leaf = true
	entry({"admin", "vpn", "vnt", "save_client"}, call("save_client")).leaf = true
	entry({"admin", "vpn", "vnt", "save_server"}, call("save_server")).leaf = true
	entry({"admin", "vpn", "vnt", "get_ifaces"}, call("get_ifaces")).leaf = true
	entry({"admin", "vpn", "vnt", "get_keys"}, call("get_keys")).leaf = true
	entry({"admin", "vpn", "vnt", "upload"}, call("do_upload")).leaf = true
	entry({"admin", "vpn", "vnt", "vnt_info"}, call("vnt_info")).leaf = true
	entry({"admin", "vpn", "vnt", "vnt_list"}, call("vnt_list")).leaf = true
	entry({"admin", "vpn", "vnt", "vnt_route"}, call("vnt_route")).leaf = true
	entry({"admin", "vpn", "vnt", "vnt_cmd"}, call("vnt_cmd")).leaf = true
end

function act_status()
	local sys = require "luci.sys"
	local uci = require "luci.model.uci".cursor()
	local e = {}
	
	e.crunning = sys.call("pgrep vnt-cli >/dev/null") == 0
	e.srunning = sys.call("pgrep vnts >/dev/null") == 0
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
	local function get_runtime(file)
		local f = io.open(file, "r")
		if f then
			local t = f:read("*all"); f:close()
			local start = tonumber(t)
			if start then
				local diff = os.time() - start
				local d, h, m = math.floor(diff/86400), math.floor((diff%86400)/3600), math.floor((diff%3600)/60)
				return d > 0 and string.format("%d天%02d时%02d分", d, h, m) or string.format("%02d时%02d分%02d秒", h, m, diff%60)
			end
		end
		return "-"
	end
	e.vntsta, e.vntsta2 = get_runtime("/tmp/vnt_time"), get_runtime("/tmp/vnts_time")
	if e.crunning then
		local pid = sys.exec("pidof vnt-cli 2>/dev/null | awk '{print $1}'"):gsub("%s+", "")
		if pid ~= "" then
			e.vntcpu = sys.exec("top -b -n1 2>/dev/null | awk '$1==" .. pid .. "{print $7; exit}'"):gsub("%s+", "")
			e.vntram = sys.exec("cat /proc/" .. pid .. "/status 2>/dev/null | awk '/VmRSS/{printf \"%.1fMB\", $2/1024}'"):gsub("%s+", "")
		end
		if not e.vntcpu or e.vntcpu == "" then e.vntcpu = "0%" end
		if not e.vntram or e.vntram == "" then e.vntram = "-" end
	else
		e.vntcpu, e.vntram = "-", "-"
	end
	if e.srunning then
		local pid = sys.exec("pidof vnts 2>/dev/null | awk '{print $1}'"):gsub("%s+", "")
		if pid ~= "" then
			e.vntscpu = sys.exec("top -b -n1 2>/dev/null | awk '$1==" .. pid .. "{print $7; exit}'"):gsub("%s+", "")
			e.vntsram = sys.exec("cat /proc/" .. pid .. "/status 2>/dev/null | awk '/VmRSS/{printf \"%.1fMB\", $2/1024}'"):gsub("%s+", "")
		end
		if not e.vntscpu or e.vntscpu == "" then e.vntscpu = "0%" end
		if not e.vntsram or e.vntsram == "" then e.vntsram = "-" end
	else
		e.vntscpu, e.vntsram = "-", "-"
	end
	e.vnttag = sys.exec("$(uci -q get vnt.@vnt-cli[0].clibin) -h 2>/dev/null | grep 'version:' | awk -F':' '{print $2}'"):gsub("%s+", "")
	e.vntstag = sys.exec("$(uci -q get vnt.@vnts[0].vntsbin) -V 2>/dev/null | awk '/^version:/{print $2; exit}'"):gsub("%s+", "")
	
	luci.http.prepare_content("application/json")
	luci.http.write_json(e)
end

function get_config()
	local uci = require "luci.model.uci".cursor()
	local e = {}
	local cs = uci:get_first("vnt", "vnt-cli")
	if cs then for k,v in pairs(uci:get_all("vnt", cs)) do e["c_"..k] = v end end
	local ss = uci:get_first("vnt", "vnts")
	if ss then for k,v in pairs(uci:get_all("vnt", ss)) do e["s_"..k] = v end end
	luci.http.prepare_content("application/json")
	luci.http.write_json(e)
end

function get_keys()
	local nixio = require "nixio"
	local e = {}
	e.public_key = nixio.fs.readfile("/tmp/vnts_key/public_key.pem") or ""
	e.private_key = nixio.fs.readfile("/tmp/vnts_key/private_key.pem") or ""
	luci.http.prepare_content("application/json")
	luci.http.write_json(e)
end

function save_client()
	local uci = require "luci.model.uci".cursor()
	local http = require "luci.http"
	local json = require "luci.jsonc"
	local section = uci:get_first("vnt", "vnt-cli")
	local data = json.parse(http.formvalue("data") or "{}")
	if data then
		local lists = {localadd=1,peeradd=1,vntdns=1,stunhost=1,mapping=1,checkip=1,vnt_forward=1}
		for k, v in pairs(data) do
			if lists[k] then
				uci:delete("vnt", section, k)
				if type(v) == "table" then
					for _, item in ipairs(v) do if item ~= "" then uci:add_list("vnt", section, k, item) end end
				elseif v ~= "" then uci:add_list("vnt", section, k, v) end
			else
				uci:set("vnt", section, k, v)
			end
		end
		uci:commit("vnt")
		luci.sys.call("/etc/init.d/vnt restart >/dev/null 2>&1 &")
	end
	http.prepare_content("application/json")
	http.write_json({status = "ok"})
end

function save_server()
	local uci = require "luci.model.uci".cursor()
	local http = require "luci.http"
	local json = require "luci.jsonc"
	local nixio = require "nixio"
	local section = uci:get_first("vnt", "vnts")
	local data = json.parse(http.formvalue("data") or "{}")
	if data then
		local lists = {white_Token=1}
		for k, v in pairs(data) do
			if k == "public_key" then
				if v ~= "" then
					nixio.fs.mkdir("/tmp/vnts_key")
					nixio.fs.writefile("/tmp/vnts_key/public_key.pem", v:gsub("\r\n", "\n"))
				end
			elseif k == "private_key" then
				if v ~= "" then
					nixio.fs.mkdir("/tmp/vnts_key")
					nixio.fs.writefile("/tmp/vnts_key/private_key.pem", v:gsub("\r\n", "\n"))
				end
			elseif lists[k] then
				uci:delete("vnt", section, k)
				if type(v) == "table" then
					for _, item in ipairs(v) do if item ~= "" then uci:add_list("vnt", section, k, item) end end
				elseif v ~= "" then uci:add_list("vnt", section, k, v) end
			else
				uci:set("vnt", section, k, v)
			end
		end
		uci:commit("vnt")
		luci.sys.call("/etc/init.d/vnt restart >/dev/null 2>&1 &")
	end
	http.prepare_content("application/json")
	http.write_json({status = "ok"})
end

function get_ifaces()
	local sys = require "luci.sys"
	local result = {}
	local ifaces = sys.exec("ls /sys/class/net 2>/dev/null")
	for iface in ifaces:gmatch("%S+") do
		local ip = sys.exec("ip -4 addr show " .. iface .. " 2>/dev/null | awk '/inet /{print $2}' | cut -d'/' -f1"):gsub("%s+", "")
		if ip ~= "" then table.insert(result, {name = iface, ip = ip}) end
	end
	luci.http.prepare_content("application/json")
	luci.http.write_json(result)
end

function do_upload()
	local http = require "luci.http"
	local fp, filename
	http.setfilehandler(function(meta, chunk, eof)
		if not fp and meta and meta.name == "file" then
			filename = meta.file
			fp = io.open("/tmp/" .. filename, "w")
		end
		if fp and chunk then fp:write(chunk) end
		if eof and fp then
			fp:close()
			if filename:match("%.tar%.gz$") then
				os.execute("tar -xzf /tmp/" .. filename .. " -C /tmp/")
			end
			os.execute("chmod +x /tmp/vnt-cli /tmp/vnts 2>/dev/null")
		end
	end)
	http.formvalue("file")
	http.prepare_content("application/json")
	http.write_json({status = "ok", file = filename})
end

function do_restart()
	luci.sys.call("/etc/init.d/vnt restart >/dev/null 2>&1 &")
	luci.http.prepare_content("application/json")
	luci.http.write_json({status = "ok"})
end

function get_log()
	local f = io.open("/tmp/vnt-cli.log", "r")
	luci.http.write(f and f:read("*all") or "暂无日志"); if f then f:close() end
end

function get_log2()
	local f = io.open("/tmp/vnts.log", "r")
	luci.http.write(f and f:read("*all") or "暂无日志"); if f then f:close() end
end

function clear_log()
	luci.sys.call("rm -f /tmp/vnt-cli*.log")
	luci.http.prepare_content("application/json")
	luci.http.write_json({status = "ok"})
end

function clear_log2()
	luci.sys.call("rm -f /tmp/vnts*.log")
	luci.http.prepare_content("application/json")
	luci.http.write_json({status = "ok"})
end

function vnt_info()
	local info = luci.sys.exec("$(uci -q get vnt.@vnt-cli[0].clibin) --info 2>&1")
	if info == "" then info = "错误：程序未运行" end
	info = info:gsub("Connection status", "连接状态"):gsub("Virtual ip", "虚拟IP")
	info = info:gsub("Virtual gateway", "虚拟网关"):gsub("Virtual netmask", "虚拟掩码")
	info = info:gsub("NAT type", "NAT类型"):gsub("Relay server", "服务器")
	info = info:gsub("Public ips", "外网IP"):gsub("Local addr", "本地地址")
	luci.http.prepare_content("application/json")
	luci.http.write_json({html = "<pre>" .. info .. "</pre>"})
end

function vnt_list()
	local list = luci.sys.exec("$(uci -q get vnt.@vnt-cli[0].clibin) --list 2>&1")
	if list == "" or list:match("[Ee]rror") then
		luci.http.prepare_content("application/json")
		luci.http.write_json({html = "<div class='empty'>程序未运行或暂无设备</div>"})
		return
	end
	local html = "<table class='dtable'><tr><th>名称</th><th>虚拟IP</th><th>状态</th><th>模式</th><th>延迟</th></tr>"
	local first = true
	for line in list:gmatch("[^\r\n]+") do
		if first then first = false else
			local cols = {}; for c in line:gmatch("%S+") do table.insert(cols, c) end
			if #cols >= 5 then
				local st = cols[3]:lower() == "online" and "on" or "off"
				local md = cols[4]:lower() == "p2p" and "p2p" or "relay"
				local rt = tonumber(cols[5]) or 0
				local rc = rt < 50 and "good" or (rt < 100 and "mid" or "bad")
				html = html .. string.format("<tr><td><b>%s</b></td><td><code>%s</code></td><td class='st-%s'>● %s</td><td class='md-%s'>%s</td><td class='rt-%s'>%sms</td></tr>",
					cols[1], cols[2], st, cols[3], md, cols[4]:upper(), rc, cols[5])
			end
		end
	end
	luci.http.prepare_content("application/json")
	luci.http.write_json({html = html .. "</table>"})
end

function vnt_route()
	local route = luci.sys.exec("$(uci -q get vnt.@vnt-cli[0].clibin) --route 2>&1")
	if route == "" then route = "程序未运行" end
	route = route:gsub("Next Hop", "下一跳"):gsub("Interface", "接口")
	luci.http.prepare_content("application/json")
	luci.http.write_json({html = "<pre>" .. route .. "</pre>"})
end

function vnt_cmd()
	local cmd = luci.sys.exec("cat /proc/$(pidof vnt-cli 2>/dev/null | awk '{print $1}')/cmdline 2>/dev/null | tr '\\0' ' '")
	if cmd == "" then cmd = "程序未运行" end
	luci.http.prepare_content("application/json")
	luci.http.write_json({html = "<pre>" .. cmd .. "</pre>"})
end
