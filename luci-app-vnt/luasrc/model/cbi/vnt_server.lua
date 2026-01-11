local m, s

m = Map("vnt", translate("vnts 设置"))
m.redirect = luci.dispatcher.build_url("admin/vpn/vnt")

s = m:section(TypedSection, "vnts")
s.anonymous = true
s:tab("gen", translate("基本设置"))
s:tab("pri", translate("高级设置"))

-- ===== 基本设置 =====
s:taboption("gen", Flag, "enabled", translate("启用")).rmempty = false

local server_port = s:taboption("gen", Value, "server_port", translate("监听端口"))
server_port.datatype = "port"
server_port.placeholder = "29872"

local white_Token = s:taboption("gen", DynamicList, "white_Token", translate("Token白名单"))
white_Token.placeholder = "留空不限制"

local subnet = s:taboption("gen", Value, "subnet", translate("DHCP网关"))
subnet.datatype = "ip4addr"
subnet.placeholder = "10.26.0.1"

local netmask = s:taboption("gen", Value, "servern_netmask", translate("子网掩码"))
netmask.placeholder = "255.255.255.0"

s:taboption("gen", Flag, "web", translate("启用WEB管理")).rmempty = false

local web_port = s:taboption("gen", Value, "web_port", translate("WEB端口"))
web_port:depends("web", "1")
web_port.datatype = "port"

local webuser = s:taboption("gen", Value, "webuser", translate("帐号"))
webuser:depends("web", "1")
webuser.password = true

local webpass = s:taboption("gen", Value, "webpass", translate("密码"))
webpass:depends("web", "1")
webpass.password = true

s:taboption("gen", Flag, "logs", translate("启用日志")).rmempty = false

-- ===== 高级设置 =====
local vntsbin = s:taboption("pri", Value, "vntsbin", translate("程序路径"))
vntsbin.placeholder = "/usr/bin/vnts"

s:taboption("pri", Flag, "sfinger", translate("指纹校验")).rmempty = false

return m
