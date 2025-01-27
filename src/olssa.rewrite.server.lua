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

-- ⚠️ Make sure to paste the auditor snippet at the beginning of the script for the intended behavior ⚠️
--================----==OLSSABEGIN==----================--
do
	-- § Internally used globals
	local _rawget = rawget; local _rawset = rawset; local _setfenv = setfenv; local _getfenv = getfenv;
	local _setmetatable = setmetatable; local _getmetatable = getmetatable;
	local _unpack = unpack; local _select = select;

	local __env = _getfenv()

	local __globals = {
		original = _setmetatable({}, {__mode = "k"}),
		custom = _setmetatable({}, {__mode = "k"})
	}
	
	-- § Configuration
	local __config = {
		["meta"] = {
			["revision"] = "rewrite";
			["date"] = "25/01/2025"; -- dd/mm/yyyy
		};

		["logs"] = {
			-- 0: Mute < 1: Script Activity & Requests < 2: Spoof Actions < 3: Wrapped Object Metamethods < 4: Detailed table, function dumps
			["verbose"] = 2;
			["whitelist"] = nil; -- Only output logs that match the whitelist Lua Pattern
			["blacklist"] = nil; -- Only output logs that don't match the blacklist Lua Pattern
			["prelogs"] = false; -- Show logs that come from OLSSA startup
			["shadow"] = true; -- Hook LogService to ignore OLSSA logs
		};

		["environment"] = {
			["wrap"] = true; -- Wraps the base environment to use a metatable with custom __index instead of using rawset for globals
			["light"] = true; -- Keeps the environment wrapping to a minimum, returning either custom values & globals, or raw values
			["usekeys"] = false; -- Uses key-based global spoofing instead of value-based in the environment wrapper
			["custom"] = {
				-- Custom environment write, useful for linking OLSSA to a VM
				["env"] = nil;
				["write"] = function(k, v, o) -- k: index, v: value, o: original
					
				end;
			};
		};

		["wrapper"] = {
			["globals"] = {"script"; "workspace"; "type"; "typeof"; "Instance"; "tostring"}; -- Globals to wrap, replace or extend, apart from spoofed ones
			["blacklist"] = {
				["enabled"] = false;
				["values"] = {}; -- If something with these values is being indexed, return the unwrapped version
				["keys"] = {}; -- If one of these keys is being indexed, return the unwrapped version
			};
		};

		["require"] = {
			["hook"] = true; -- Enable require hook
			["spoof"] = true; -- Hook should look up a local version of an external require
			["folder"] = workspace; -- Spoofed local modules folder
			["prefix"] = "OLSSA:"; -- Naming scheme used by local modules for spoofing, prefix + assetid
			["lookup"] = function(self, module: number)
				-- Spoof ModuleScript Instance to return when require is called with an AssetId
				-- Lookup function can be edited to access differently named modules based on id or for other use cases
				return self.folder:WaitForChild(string.format("%s%d", self.prefix, module), 15)
			end;
			["name"] = "MainModule"; -- Any ModuleScript matching the OLSSA prefix that is being indexed through a wrapped object, will have this spoofed name
			["sandbox"] = true; -- Iterates through ModuleScript returned data and sets all function environments to this one
								-- !NOTE: tostring(getfenv()) would be the same across this script and then ModuleScript, this shouldn't be the case, DETECTABLE!
		};
		["game"] = {
			["hook"] = true; -- Replace game global with custom version
			["creator"] = {
				["spoof"] = true; -- Enable creator spoof
				["type"] = "User"; -- "User"/"Group"
				["id"] = 123456789; -- Creator Id
			};
			["universe"] = {
				["spoof"] = true; -- Enable universe id spoof
				["id"] = 123456789; -- Universe Id
			};
			["place"] = {
				["spoof"] = true; -- Enable place id spoof
				["id"] = 123456789; -- Universe Id
			};
		};
		["httpservice"] = {
			["spoof"] = true; -- Spoofs game's HttpService with a custom version, 'game' hook must be enabled
			["httpenabled"] = true; -- Spoofs HttpEnabled with the desired value, use nil to keep the original value
		};
		["runservice"] = {
			["spoof"] = true; -- Spoofs game's RunService with a custom version, 'game' hook must be enabled
			["isstudio"] = true; -- Spoofs IsStudio with the desired value, use nil to keep the original value
		};
		["marketplaceservice"] = {
			["spoof"] = true; -- Spoofs game's MarketplaceService with a custom version, 'game' hook must be enabled
			["check"] = true; -- Before spoofing ownership status, it calls the original API and throws any errors to replicate behavior
			["gamepasses"] = { -- Spoofs MarketplaceService's UserOwnsGamePassAsync calls to return custom ownership statuses for specific passes and users
			--[[
				{
					userid = 000000000;
					gamepassid = 000000000;
					owns = true;
				};
			]]
			};
			-- !NOTE: Script can only use this with a valid Player, olssa checks that player's userid and spoofs if it matches 
			["assets"] = { -- Spoofs MarketplaceService's UserOwnsGamePassAsync calls to return custom ownership statuses for specific passes and users
			--[[
				{
					userid = 000000000;
					assetid = 000000000;
					owns = true;
				};
			]]
			};
		};

		-- !NOTE: Instead of sandboxing by setting the fenv and iterating, just wrap the modulescript result
		-- (and edit wrapper to automatically return custom env values), tell wrapper it is a modulescript so it changes the tostring 
		-- of getfenv to another random table value that is different
	};

	-- § Internally used globals
	local __script = script; local __game = game; local __workspace = workspace;

	local __type = type; local __typeof = typeof;
	local __tostring = tostring;
	local __debug = debug;

	if __config.environment.custom.env ~= nil then
		__env = __config.environment.custom.env
	end
	local function _env_write(k: string, v: any, o: any?)
		local clean = _rawget(__env, k)
		-- !NOTE: If original_value is nil, instead of using rawset, we'll add the new global to a table that will be indexed in a wrapped (maybe lighter than olssa wrap) environment
		-- Store original value under global name for potential restoration
		__globals.original[k] = if clean ~= nil then clean else o;
		__globals.custom[k] = v
		-- Create reverse mapping from original value to spoofed value
		-- Only if original exists (nil values can't be table keys)
		if clean ~= nil then
			__globals.original[clean] = v
			__globals.custom[v] = v
		else
			if o ~= nil then
				__globals.original[o] = v
				__globals.custom[o] = v
			end

			-- handle original[o] = k if o ~= nil
			if __config.environment.wrap then
				-- Let wrapped environment handle custom globals
				return
			end
		end

		if __config.environment.custom.env ~= nil then
			__config.environment.custom.write(k, v, o)
		end
		
		-- Securely set the new value in environment
		return _rawset(__env, k, v)
	end

	-- Generate a unique OLSSA-session identifier, which can be used to string match logs (and hide them if hooking LogService)
	-- __identifier --> "%451676bcada921d7%"
	local __identifier = string.format("%%%04x%04x%04x%04x%%", math.random(0, 0xFFFF), math.random(0, 0xFFFF), math.random(0, 0xFFFF), math.random(0, 0xFFFF));
	local __timestamp = -os.clock(); -- Redefined later with positive timestamp, negative timetamp is then an indicator of an error in OLSSA itself

	-- Assigns a custom tag to the OLSSA thread in the Developer Console for memory usage analysis
	__debug.setmemorycategory(string.format("%s - OLSSA %s %s", __script.Name, __config.meta.revision, __identifier))

	-- § Logging
	local _log = __config.logs.verbose > 0 and function(level: number, ...: any)
		if level > __config.logs.verbose then
			return
		end
		if math.sign(__timestamp) ~= 1 and not __config.logs.prelogs then
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
	
				local name = fullname and _select(1, fullname:gsub(__script:GetFullName(), "(script)")) or "(main)" --fullname:match("[^%.]+$") or "Unknown"
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
				dump[i] = if __config.logs.verbose >= 4 then __dump(v, 0, {}) else __tostring(v)
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
	end or function(...) end;

	-- § Wrapper
	local _wrapper = (function()
		local self = {}
	
		-- Weak cache tables with string-based keys for security
		local __cache = {
			original = _setmetatable({}, {__mode = "k"}),
			wrapped = _setmetatable({}, {__mode = "k"})
		}

		-- During configuration initialization
		local __blacklist = {
    		keys = _setmetatable({}, {__mode = "k"}),
    		values = _setmetatable({}, {__mode = "v"})
		}

		-- Convert array blacklists to hash tables once during init
		for _, k in ipairs(__config.wrapper.blacklist.keys) do
  			__blacklist.keys[k] = true
		end

		for _, v in ipairs(__config.wrapper.blacklist.values) do
		    __blacklist.values[v] = true
		end

		-- Core wrapper method with security hardening
		function self:wrap(obj: any, cnt: {}?, light: boolean?, isenv: boolean?): any
			if obj == nil then return nil end

			if __cache.wrapped[obj] then return __cache.wrapped[obj] end
	
			local obj_type = __type(obj)
			
			-- Userdata proxy with native behavior preservation
			if obj_type == "userdata" then
				local wrapped = newproxy(true)
				local meta = _getmetatable(wrapped)
				
				meta.__index = function(_, k)
					
					local raw_value = obj[k]
					_log(3, "USERDATA_GET", obj, k, raw_value)

					if __config.wrapper.blacklist.enabled then
						if (__blacklist.keys[k] ~= nil) or (__blacklist.values[raw_value] ~= nil) then
							_log(3, "USERDATA_RAW_VALUE", obj, k, raw_value)
							return raw_value
						end
					end
					
					-- If we're indexing a global that we're spoofing, return it
					local spoofed_value = cnt and cnt[k]
					if spoofed_value ~= nil then
						_log(3, "USERDATA_VALUE_SPOOF", obj, k, spoofed_value)
						return self:wrap(spoofed_value)
					end

					-- If we're indexing a global (or index points to original global) that we're spoofing, return the spoofed version
					local spoofed_global = if isenv then __globals.custom[k] else __globals.custom[raw_value]
					if spoofed_global ~= nil then
						_log(3, "USERDATA_GLOBAL_SPOOF", obj, k, spoofed_global)
						return self:wrap(spoofed_global)
					end

					if light then return raw_value end

					return self:wrap(raw_value)
				end			
	
				meta.__newindex = function(_, k: string, v: any)
					_log(3, "USERDATA_SET", obj, k, v)
					obj[k] = self:unwrap(v)
				end
	
				meta.__tostring = function()
					return tostring(obj)
				end
	
				meta.__metatable = _getmetatable(obj)
				__cache.wrapped[obj] = wrapped
				__cache.original[wrapped] = obj
				return wrapped
	
			-- Table proxy with access monitoring
			elseif obj_type == "table" then
				local wrapped = {}
				__cache.wrapped[obj] = wrapped
				__cache.original[wrapped] = obj
	
				_setmetatable(wrapped, {
					__index = function(_, k: any): any
						local raw_value = obj[k]
						_log(3, "TABLE_GET", obj, k, raw_value)

						if __config.wrapper.blacklist.enabled then
							if (__blacklist.keys[k] ~= nil) or (__blacklist.values[raw_value] ~= nil) then
								_log(3, "TABLE_RAW_VALUE", obj, k, raw_value)
								return raw_value
							end
						end
						
						-- If we're indexing a global that we're spoofing, return it
						local spoofed_value = cnt and cnt[k]
						if spoofed_value ~= nil then
							_log(3, "TABLE_VALUE_SPOOF", obj, k, spoofed_value)
							return self:wrap(spoofed_value)
						end
	
						-- If we're indexing a global (or index points to original global) that we're spoofing, return the spoofed version
						local spoofed_global = if isenv then __globals.custom[k] else __globals.custom[raw_value]
						if spoofed_global ~= nil then
							_log(3, "TABLE_GLOBAL_SPOOF", obj, k, spoofed_global)
							return self:wrap(spoofed_global)
						end

						if light then return raw_value end

						return self:wrap(raw_value)
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
			elseif obj_type == "function" then
				_log(3, "WRAP_FUNCTION", obj)
				local wrapped = function(...: any): ...any
					_log(4, "CALL_FUNCTION", obj, ...)
					local args = {...}
					for i = 1, _select('#', ...) do
						args[i] = self:unwrap(args[i])
					end
	
					local success, results = pcall(obj, _unpack(args))
					if not success then
						error(results, 2)
					end
	
					results = {results}
					for i = 1, #results do
						results[i] = self:wrap(results[i])
					end
					return _unpack(results)
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

	
	-- § Wrap/write globals
	-- !NOTE: rawget(__env, global) result should not be different after _env_write
	for _, global in __config.wrapper.globals do
		if __type(global) == "string" and __env[global] then
			_env_write(global, _wrapper:wrap(__env[global]), __env[global]) -- key, wrapped, original
		elseif __type(global) == "table" and global.k and global.cnt and __env[global.k] then
			_env_write(global.k, _wrapper:wrap(__env[global.k], global.cnt), __env[global.k])
		elseif __type(global) == "table" and global.k and global.v and __env[global.k] then
			_env_write(global.k, _wrapper:wrap(global.v), __env[global.k])
		end
	end

	-- § 'LogService' Shadow OLSSA Logs Spoof
	-- § 'require' Hook
	local __require = require
	_env_write("require", function(v: ModuleScript|any?)
		if __type(v) == 'number' then
			-- Require has been called with an AssetId
			_log(1, "REQUIRE_EXT", v)
			if __config.require.spoof then
				local mobj = __config.require:lookup(v)
				if mobj ~= nil then
					_log(2, "REQUIRE_SPOOF", v, mobj.Name)
					v = mobj
				else
					_log(2, "REQUIRE_RAW", v)
				end
			end
		else
			v = _wrapper:unwrap(v) -- Unwrap module, as it could cause issues being accepted by require function
			if __typeof(v) == 'Instance' then
				-- Require has been called with a local modulescript
				_log(1, "REQUIRE_INT", v:GetFullName())
			else
				-- Require has been called with an unknown value type
				_log(1, "REQUIRE_UNK", __type(v), __typeof(v), v)
			end
		end
		local o = __require(v)
		_log(1, "REQUIRE_DATA", {o})
		return _wrapper:wrap(o)
	end, __require)

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
	
	if __config.game.hook then
		_env_write("game", _wrapper:wrap(game, {
			CreatorId = if __config.game.creator.spoof then __config.game.creator.id else __game.CreatorId,
			CreatorType = if __config.game.creator.spoof then Enum.CreatorType:FromName(__config.game.creator.type) else __game.CreatorType,
			GameId = if __config.game.universe.spoof then __config.game.universe.id else __game.GameId,
			PlaceId = if __config.game.place.spoof then __config.game.place.id else __game.PlaceId,
			--GetService = function(self, s)
			--end
		}), game)
	end
	
	--_env_write("workspace", _wrapper:wrap(workspace))
	--_env_write("print", _wrapper:wrap(print))

	-- § Wrap environment
	if __config.environment.wrap then
		_setfenv(1, _wrapper:wrap(__env, nil, __config.environment.light, __config.environment.usekeys))
	end

	__debug.resetmemorycategory() -- Reset thread developer console tag
	__timestamp = os.clock(); -- Reset timestam
end -- ⚠️ OLSSA Auditor Snippet End ⚠️
--================----===OLSSAEND===----================--

-- Benchmark performance
local start = os.clock()
--for i=1,1e6 do game:GetService("Workspace") end
--print("Wrapped access time:", os.clock()-start) -- Target <0.1s
print(rawget(getfenv(), "require"), require, rawget(getfenv(), "game"), game.CreatorId, workspace.Parent.CreatorId)
--print(require(script.Parent["OLDolssa.rewrite copy"]))
print(require(145458))
--print(getmetatable(getfenv()), rawget(getfenv(), "game"), typeof(game), game.CreatorId, workspace.Parent.CreatorId, game == workspace.Baseplate.Parent.Parent, tostring(game), getmetatable(game))
