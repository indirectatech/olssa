--!native
--!nonstrict
--[[

    `/shdmmmmmmmmmd-`ymmmddyo:`       //                sm- /h/                        --
  `yNMMMMMMMMMMMMm-.dMMMMMMMMMN+     `MN  `-:::.`   .-:-hM- -o-  .-::.  .::-.   `.:::` MN--. `-::-.
  yMMMMMMMMMMMMMd.:NMMMMMMMMMMMM+    `MN  yMs+oNh  oNy++mM- +Mo -Mm++:`hmo+yN+ .dmo++- MNoo/ `o+odN:
  yMMMMMMMMMMMMy`+NMMMMMMMMMMMMM+    `MN  yM:  dM. MN   yM- +Mo -Mh   /Mmss    sM+     MN    +h ohMo
  `yNMMMMMMMMMo`sMMMMMMMMMMMMMNo     `MN  yM:  dM. oNy//dM- +Mo -Mh   `dNs++o. -mm+//- dM+/+ mN+/sMo
    `/shddddd/ odddddddddddho:`       ::  .:`  -:   `:///-` .:. `:-     .://:`  `-///. `-//: `-///:.
   ___  _     ____ ____    _
  / _ \| |   / ___/ ___|  / \     (v)
 | | | | |   \___ \___ \ / _ \   //-\\
 | |_| | |___ ___) |__) / ___ \  (\_/)
  \___/|_____|____/____/_/   \_\ _v v_

  Obfuscated Luau Script Security Audtor (OLSSA) by  ( / ) Indirecta

  (i) Licensed under the GNU General Public License v3.0
		<https://www.gnu.org/licenses/gpl-3.0.html>
]]

-- ⚠️ Make sure to use the auditor at the top of any script to prevent environment leaks ⚠️
do
	-- !NOTE: DO NOT declare globals anywhere; Declare local variables ONLY INSIDE THE DO, otherwise it will be accessible to code below auditor

	 -- Base Environment & Original Globals
	local _rawget = rawget;
	local _rawset = rawset;
	local _setfenv = setfenv;
	local _getfenv = getfenv;

	local __env = _getfenv()
	local __globals = {}
	local __wglobals = {}

	-- § Configuration
	local __config = {
		["meta"] = {
			["revision"] = "rewrite";
			["date"] = "23/01/2025"; -- dd/mm/yyyy
		};

		["logs"] = {
			["verbose"] = 4; -- 0: Mute < 1: Script Activity & Requests < 2: Spoof Actions < 3: Wrapped Object Metamethods 
			["whitelist"] = nil; -- Only output logs that match the whitelist Lua Pattern
			["blacklist"] = nil; -- Only output logs that don't match the blacklist Lua Pattern
			["shadow"] = true; -- Hook LogService to ignore OLSSA logs
		};

		["environment"] = {
			["wrap"] = true; -- If enabled, wraps the base environment to use a metatable with custom __index instead of using rawset for globals
		};
		["wrapper"] = {
			["globals"] = {"script"; "workspace"; "type"; "typeof"; "Instance"}; -- Globals to wrap, apart from spoofed ones
			["gameservices"] = true; -- Wraps other non-spoofed game services --!NOTE: Make sure wrapper does not wrap game services if this is disabled

		};

		["require"] = {
			["spoof"] = true;
			["folder"] = workspace;
			["prefix"] = "OLSSA:";
			["lookup"] = function(self, module: number)
				-- Spoof ModuleScript Instance to return when require is called with an AssetId
				-- Lookup function can be edited to access differently named modules based on id, for example
				return self.folder:WaitForChild(string.format("%s%d", self.prefix, module), 15)
			end;
			["name"] = "MainModule"; -- Any ModuleScript matching the OLSSA prefix, that is being indexed through a wrapped object, will have this spoofed name
			["sandbox"] = true; -- Iterates through ModuleScript returned data and sets all function environments to this one
								-- !NOTE: tostring(getfenv()) would be the same across this script and then ModuleScript, this shouldn't be the case, DETECTABLE!
		};
		["httpservice"] = {};

		-- !NOTE: Instead of sandboxing by setting the fenv and iterating, just wrap the modulescript result
		-- (and edit wrapper to automatically return custom env values), tell wrapper it is a modulescript so it changes the tostring 
		-- of getfenv to another random table value that is different
	};
	
	local function _env_write(k, v)
		local original_value = _rawget(__env, k)
		-- Store original value under global name for potential restoration
		__globals[k] = original_value
		-- Create reverse mapping from original value to spoofed value
		-- Only if original exists (nil values can't be table keys)
		if original_value ~= nil then
			__globals[original_value] = v
		end
		
		-- Securely set the new value in environment
		if not __config.environment.wrap then
			return _rawset(__env, k, v)
		else
			__wglobals[k] = v
		end
		return
	end

	-- write env spoofing function
	-- saves to a backup "old" table the original globals
	-- overwrites __env global

	local __script = script;
	local __game = game;
	local __workspace = workspace;

	local __type = type;
	local __typeof = typeof;
	local __tostring = tostring;
	local __debug = debug;


	-- Generate a unique OLSSA-session identifier, which can be used to string match logs (and hide them if hooking LogService)
	-- __identifier --> "%451676bcada921d7%"
	local __identifier = string.format("%%%04x%04x%04x%04x%%", math.random(0, 0xFFFF), math.random(0, 0xFFFF), math.random(0, 0xFFFF), math.random(0, 0xFFFF));
	local __timestamp = -os.clock(); -- Redefined later with positive timestamp, negative timetamp is then an indicator of an error in OLSSA itself

	-- Assigns a custom tag to the OLSSA thread in the Developer Console for memory usage analysis
	__debug.setmemorycategory(string.format("%s - OLSSA %s %s", __script.Name, __config.meta.revision, __identifier))

	-- § Logging
	local _log = function(level: number, ...: any)
		if __config.logs.verbose == 0 or level > __config.logs.verbose then
			return
		end
		local function processStackTrace(trace: string): string
			local stack = {}
			local traceLines = trace:split("\n")
			
			for i = #traceLines, 1, -1 do
				local line = traceLines[i]:gsub("^%s+", ""):gsub("%s+$", "")
				if line == "" then continue end

				local fullname, number, _ = line:match("^(.+):(%d+)")
				local _, _, func = line:match("^(.+):(%d+)%sfunction%s(.+)$")

				if not number then continue end
	
				local name = fullname and select(1, fullname:gsub(__script:GetFullName(), "(script)")) or "(main)" --fullname:match("[^%.]+$") or "Unknown"
				local entry = func and string.format("%s.%s:%s", name, func, number)
							  or string.format("%s:%s", name, number)
				
				table.insert(stack, entry)
			end
			
			return "| Stack Begin >  " .. table.concat(stack, " → ") .. "  < Stack End |"
		end
		
			
		local timestamp = math.sign(__timestamp) * math.round((os.clock() - math.abs(__timestamp)) * 1000)
		local header = string.format("[OLSSA] %s (l%d %dms)", __script:GetFullName(), level, timestamp)
		local content = table.concat((function(args)
			local function __dump(val, indent, visited)
				indent = indent or 0
				visited = visited or {}
				local ty = __type(val)
				
				if ty == "table" then
					if visited[val] then return "<cyclic table>" end
					visited[val] = true
					
					local parts = {string.rep("  ", indent) .. "{"}
					for k, v in pairs(val) do
						local keyStr = __tostring(k)
						local valueStr = __dump(v, indent + 1, visited)
						table.insert(parts, string.rep("  ", indent + 1).."|→ "..keyStr..": "..valueStr)
					end
					table.insert(parts, string.rep("  ", indent) .. "}")
					return table.concat(parts, "\n")
				elseif ty == "function" then
					local name = __debug.info(val, "n") or "anon"
					local nargs, variadic = __debug.info(val, "a")
					local addr = tostring(val):match("(0x%x+)$") or "0x----"
					return string.format("ƒ[%s](%d%s) @%s", name, nargs, variadic and "+" or "", addr)
				elseif ty == "string" then
					return string.format("%q", val)
				else
					return tostring(val)
				end
			end
			
			local dump = {};
			for i, v in ipairs(args) do
				dump[i] = __dump(v, 0, {})
			end
			return dump
		end)({...}), ", ")

		if __config.logs.whitelist and not string.match(content, __config.logs.whitelist) then
			return
		end

		if __config.logs.blacklist and string.match(content, __config.logs.blacklist) then
			return
		end

		local stacktrace = processStackTrace(__debug.traceback())
		local indent = string.rep(" ", 16) -- Padding for Roblox Output Console timestamp

		return warn(table.concat({header, content, __identifier}, " :: "), "\n" .. indent .. stacktrace)
	end;

	-- § Wrapper
	local _wrapper = (function()
		local self = {}
	
		-- Weak cache tables with string-based keys for security
		local __cache = {
			original = setmetatable({}, {__mode = "k"}),
			wrapped = setmetatable({}, {__mode = "k"})
		}
	
		local function __raw_type(obj: any): string
			return __type(obj)--__typeof(rawget(obj, "::original::") or obj)
		end

		-- Core wrapper method with security hardening
		function self:wrap(obj: any, cnt: {}?): any
			if obj == nil then return nil end

			if __cache.wrapped[obj] then return __cache.wrapped[obj] end
	
			local original_type = __raw_type(obj)
			
			-- Userdata proxy with native behavior preservation
			if original_type == "userdata" then
				local wrapped = newproxy(true)
				local meta = getmetatable(wrapped)
				
				meta.__index = function(_, k)
					local raw_value = obj[k]
					_log(3, "USERDATA_GET", obj, k, raw_value)
					
					-- If we're indexing a global that we're spoofing, return it
					local spoofed_value = cnt and cnt[k]
					if cnt and spoofed_value ~= nil then
						_log(2, "USERDATA_VALUE_SPOOF", obj, k, spoofed_value)
						return self:wrap(spoofed_value)
					end

					-- If we're indexing a global (or index points to original global) that we're spoofing, return the spoofed version
					local spoofed_global =  __globals[raw_value]
					if spoofed_global ~= nil then
						_log(2, "USERDATA_GLOBAL_SPOOF", obj, k, spoofed_global)
						return self:wrap(spoofed_global)
					end
					
					return self:wrap(raw_value)
				end			
	
				meta.__newindex = function(_, key: string, value: any)
					_log(3, "USERDATA_SET", obj, key, value)
					obj[key] = self:unwrap(value)
				end
	
				meta.__tostring = function()
					return tostring(obj)
				end
	
				meta.__metatable = getmetatable(obj)
				__cache.wrapped[obj] = wrapped
				__cache.original[wrapped] = obj
				return wrapped
	
			-- Table proxy with access monitoring
			elseif original_type == "table" then
				local wrapped = {}
				__cache.wrapped[obj] = wrapped
				__cache.original[wrapped] = obj
	
				setmetatable(wrapped, {
					__index = function(_, k: any): any
						local raw_value = obj[k]
						_log(3, "TABLE_GET", obj, k)

						-- If we're indexing a global that we're spoofing, return it
						local spoofed_value = cnt and cnt[k]
						if cnt and spoofed_value ~= nil then
							_log(2, "TABLE_VALUE_SPOOF", obj, k, spoofed_value)
							return self:wrap(spoofed_value)
						end

						-- If we're indexing a global (or index points to original global) that we're spoofing, return the spoofed version
						local spoofed_global = __globals[raw_value]
						if spoofed_global ~= nil then
							_log(2, "TABLE_GLOBAL_SPOOF", obj, k, spoofed_global)
							return self:wrap(spoofed_global)
						end
						return self:wrap(obj[k])
					end,
					
					__newindex = function(_, k: any, v: any)
						_log(3, "TABLE_SET", obj, k)
						obj[k] = self:unwrap(v)
					end,
					
					__iter = function()
						local next_fn, state, init = pairs(obj) -- CAREFUL HERE!
						return function()
							local k, v = next_fn(state, init)
							init = k
							return self:wrap(k), self:wrap(v)
						end
					end
				})
				return wrapped
	
			-- Function wrapper with call monitoring
			elseif original_type == "function" then
				_log(3, "WRAP_FUNCTION", obj)
				local wrapped = function(...: any): ...any
					_log(4, "CALL_FUNCTION", obj, ...)
					local args = table.pack(...)
					for i = 1, #args do
						args[i] = self:unwrap(args[i])
					end
	
					local success, results = pcall(obj, table.unpack(args, 1, #args))
					if not success then
						error(results, 2)
					end
	
					results = table.pack(results)
					for i = 1, #results do
						results[i] = self:wrap(results[i])
					end
					return table.unpack(results, 1, #results)
				end
	
				__cache.wrapped[obj] = wrapped
				__cache.original[wrapped] = obj
				return wrapped
			end
	
			return obj
		end
	
		-- Optimized unwrap method
		function self:unwrap(obj: any): any
			return __cache.original[obj] or obj
		end
	
		return self
	end)()

	-- § Wrap globals
	-- !NOTE: rawget(__env, global) should always be nil?
	for _, global in __config.wrapper.globals do
		if __env[global] then
			_env_write(global, _wrapper:wrap(__env[global]))
		end
	end

	-- § 'LogService' Shadow OLSSA Logs Spoof
	-- § 'require' Hook
	-- § 'game:GetService' Hook and ID Spoof
	-- § 'HttpService' Traffic Hook & Enabled Spoof
	-- § 'MarketplaceService' Select-product ownership Spoof
	-- § 'DatastoreService' Traffic Hook

	--[[_game = __olssa_wrap(oldGame,{
		GetService = function(self, service)
			__olssa_verb("GetService called with Service: "..tostring(service))
			if service == "HttpService" then
				return customHttpService or oldHttpService
			elseif service == "MarketplaceService" then
				return customMarketplaceService or oldMarketplaceService
			elseif service == "RunService" then
				return customRunService or oldRunService
			elseif __olssa_configuration.WRAP_GAMESERVICES_SEC then
				return __olssa_wrap(oldGame:GetService(service))
			end
			return oldGame:GetService(service)
		end,
		CreatorId = __olssa_configuration.CREATOR_SPOOF and tonumber(__olssa_configuration.CREATOR_OBJ["CreatorId"]) or oldGame.CreatorId,
		CreatorType = __olssa_configuration.CREATOR_SPOOF and __olssa_configuration.CREATOR_OBJ["CreatorType"] or oldGame.CreatorType,
		GameId = __olssa_configuration.GAMEID_SPOOF and tonumber(__olssa_configuration.GAMEID_OBJ["GameId"]) or oldGame.GameId,
		PlaceId = __olssa_configuration.GAMEID_SPOOF and tonumber(__olssa_configuration.GAMEID_OBJ["PlaceId"]) or oldGame.PlaceId,
	})]]
	_env_write("game", _wrapper:wrap(game))
	_env_write("print", _wrapper:wrap(print))

	-- § Wrap environment
	if __config.environment.wrap then
		_setfenv(1, _wrapper:wrap(__env, __wglobals)) --, __wglobals
	end

	_log(1, "test lol wow")
	local function test()
		_log(1, "test2 lol wow")
		print({["he"] = "lol"; test = true; lol = function(ok, ...) end;})
		print(rawget(getfenv(), "game"), typeof(game), game.CreatorId, workspace.Parent.CreatorId, game == workspace.Parent, game == __env["game"], tostring(game), getmetatable(game))
	end
	test()

	__debug.resetmemorycategory() -- Reset thread developer console tag
	__timestamp = os.clock(); -- Reset timestam
end -- ⚠️ OLSSA Auditor Snippet End ⚠️

