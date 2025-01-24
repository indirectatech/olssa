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

	local function _env_write(k,v)
		--  !NOTE: If someone were to iterate through __env, they would be able to find extra spoofed globals
		__globals[k] = _rawget(__env, k);
		return _rawset(__env, v);
	end;

	-- write env spoofing function
	-- saves to a backup "old" table the original globals
	-- overwrites __env global

	local __script = script;
	local __game = game;
	local __workspace = workspace;

	local __type = type;
	local __typeof = typeof;

	local __config = {
		-- What is a hook? A hook is when OLSSA redefines a global variable to modify specific behaviors
		-- What is a spoof? A spoof is when OLSSA uses a hook to return a different value from the original

		["meta"] = {
			["revision"] = "rewrite";
			["date"] = "23/01/2025"; -- dd/mm/yyyy
		};

		["logs"] = {
			["verbose"] = 3; -- 0: Mute < 1: Script Activity & Requests < 2: Spoof Actions < 3: Wrapped Object Metamethods 
			["whitelist"] = nil; -- Only output logs that match the whitelist Lua Pattern
			["blacklist"] = nil; -- Only output logs that don't match the blacklist Lua Pattern
			["shadow"] = true; -- Hook LogService to ignore OLSSA logs
		};

		["environment"] = {

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


	-- Generate a unique OLSSA-session identifier, which can be used to string match logs (and hide them if hooking LogService)
	-- __identifier --> "%451676bcada921d7%"
	local __identifier = string.format("%%%04x%04x%04x%04x%%", math.random(0, 0xFFFF), math.random(0, 0xFFFF), math.random(0, 0xFFFF), math.random(0, 0xFFFF));
	local __timestamp = -os.clock(); -- Redefined later with positive timestamp, negative timetamp is then an indicator of an error in OLSSA itself

	-- Assigns a custom tag to the OLSSA thread in the Developer Console for memory usage analysis
	debug.setmemorycategory(string.format("%s - OLSSA %s %s", script.Name, __config.meta.revision, __identifier))

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
	
				local name = fullname and select(1, fullname:gsub(script:GetFullName(), "(script)")) or "(main)" --fullname:match("[^%.]+$") or "Unknown"
				local entry = func and string.format("%s.%s:%s", name, func, number)
							  or string.format("%s:%s", name, number)
				
				table.insert(stack, entry)
			end
			
			return "| Stack Begin >  " .. table.concat(stack, " → ") .. "  < Stack End |"
		end
		
			
		local timestamp = math.sign(__timestamp) * math.round((os.clock() - math.abs(__timestamp)) * 1000)
		local header = string.format("[OLSSA] %s (l%d %dms)", script:GetFullName(), level, timestamp)
		local content = table.concat((function(args)
			for i,v in args do
				args[i] = tostring(v)
			end
			return args
		end)({...}), ", ")

		if __config.logs.whitelist and not string.match(content, __config.logs.whitelist) then
			return
		end

		if __config.logs.blacklist and string.match(content, __config.logs.blacklist) then
			return
		end

		local stacktrace = processStackTrace(debug.traceback())
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
		function self:wrap(obj: any): any
			if obj == nil then return nil end
			if __cache.wrapped[obj] then return __cache.wrapped[obj] end
	
			local original_type = __raw_type(obj)
			
			-- Userdata proxy with native behavior preservation
			if original_type == "userdata" then
				local wrapped = newproxy(true)
				local meta = getmetatable(wrapped)
				
				meta.__index = function(_, key: string): any
					local raw_value = obj[key]
					_log(3, "USERDATA_GET", obj, key, raw_value)
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
						_log(3, "TABLE_GET", obj, k)
						return self:wrap(obj[k])
					end,
					
					__newindex = function(_, k: any, v: any)
						_log(3, "TABLE_SET", obj, k)
						obj[k] = self:unwrap(v)
					end,
					
					__iter = function()
						local next_fn, state, init = pairs(obj)
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

	__env["game"] = _wrapper:wrap(game)
	__env["workspace"] = _wrapper:wrap(workspace)

	_log(1, "test lol wow")
	local function test()
		_log(1, "test2 lol wow")
		print(game.CreatorId, workspace.Parent.CreatorId, game == workspace.Parent, game == __env["game"], tostring(game), getmetatable(game))
	end
	test()
	
	debug.resetmemorycategory() -- Reset thread developer console tag
	__timestamp = os.clock(); -- Reset timestam
end -- ⚠️ OLSSA Auditor Snippet End ⚠️

