--[[
LuCI - Lua Configuration Interface

Copyright 2014 bywayboy <bywayboy@qq.com>

]]--

module("luci.controller.phddns", package.seeall)

function index()
	
	local page
                   
	if nixio.fs.access("/etc/config/phddns") then
		page = entry({"admin", "services", "phddns"}, cbi("admin_services/phddns"), _("Oray DDNS"))
		page.dependent = true
		
		page = entry({"admin", "services", "subversion"},cbi("admin_services/subversion"), _("Subversion"))
		page.dependent = true
		
		entry({"admin", "services", "phddns_status"}, call("action_phddns_status"))

		page = entry({"admin", "services", "vlmcsd"},cbi("admin_services/vlmcsd"), _("KMS Server"))
		page.dependent = true
	end
end


function action_phddns_status()
	local file="/tmp/phddns.stat"
	local _ = luci.i18n.translate
	local stat="Not Running"
	local domain = ""
	luci.http.prepare_content("application/json")
	if nixio.fs.access(file) then
		local str = nixio.fs.readfile(file)
		stat, domain = str:match("([^|]+)|([^|]+)")
	end
	local arr = { ["stat"]=stat,["domain"]=domain }
	luci.http.write_json(arr);	
end