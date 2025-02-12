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
	local _rawget = rawget
	local _rawset = rawset
	local _setfenv = setfenv
	local _getfenv = getfenv
	local _setmetatable = setmetatable
	local _getmetatable = getmetatable
	local _unpack = unpack
	local _select = select

	local __env = _getfenv()

	local __globals = {
		original = _setmetatable({}, { __mode = "k" }),
		custom = _setmetatable({}, { __mode = "k" }),
	}

	-- § Configuration
	local __config = {
		["meta"] = {
			["revision"] = "rewrite",
			["date"] = "25/01/2025", -- dd/mm/yyyy
		},

		["logs"] = {
			-- 0: Mute < 1: Script Activity & Requests < 2: Spoof Actions < 3: Wrapped Object Metamethods < 4: Detailed table, function dumps
			["verbose"] = 0,
			["whitelist"] = nil, -- Only output logs that match the whitelist Lua Pattern
			["blacklist"] = nil, -- Only output logs that don't match the blacklist Lua Pattern
			["prelogs"] = false, -- Show logs that come from OLSSA startup
			["shadow"] = true, -- Hook LogService to ignore OLSSA logs
		},

		["environment"] = {
			["wrap"] = true, -- Wraps the base environment to use a metatable with custom __index instead of using rawset for globals
			["light"] = true, -- Keeps the environment wrapping to a minimum, returning either custom values & globals, or raw values
			["usekeys"] = false, -- Uses key-based global spoofing instead of value-based in the environment wrapper
			["custom"] = {
				-- Custom environment write, useful for linking OLSSA to a VM
				["env"] = nil,
				["write"] = function(k, v, o) -- k: index, v: value, o: original
				end,
			},
		},

		["wrapper"] = {
			["globals"] = { "script", "workspace", "type", "typeof", "Instance", "tostring" }, -- Globals to wrap, replace or extend, apart from spoofed ones
			["blacklist"] = {
				["enabled"] = false,
				["values"] = {}, -- If something with these values is being indexed, return the unwrapped version
				["keys"] = {}, -- If one of these keys is being indexed, return the unwrapped version
			},
		},

		["require"] = {
			["hook"] = true, -- Enable require hook
			["spoof"] = true, -- Hook should look up a local version of an external require
			["folder"] = workspace, -- Spoofed local modules folder
			["prefix"] = "OLSSA:", -- Naming scheme used by local modules for spoofing, prefix + assetid
			["lookup"] = function(self, module: number)
				-- Spoof ModuleScript Instance to return when require is called with an AssetId
				-- Lookup function can be edited to access differently named modules based on id or for other use cases
				return self.folder:WaitForChild(string.format("%s%d", self.prefix, module), 15)
			end,
			["mock"] = true, -- Any ModuleScript matching the OLSSA prefix that is being indexed through a wrapped object, will have a mock "MainModule" name and required_asset model hierarchy
			["sandbox"] = true, -- Iterates through ModuleScript returned data and sets all function environments to this one
			-- !NOTE: tostring(getfenv()) would be the same across this script and then ModuleScript, this shouldn't be the case, DETECTABLE!
		},
		["time"] = {
			["hook"] = true, -- Hook global functions like os.clock, time, tick, task.wait, wait, task.delay
			["dilation"] = 0.15, -- Clock dilation multiplier, can be used to spoof benchmark results
		},
		["game"] = {
			["hook"] = true, -- Replace game global with custom version
			["creator"] = {
				["spoof"] = true, -- Enable creator spoof
				["type"] = "User", -- "User"/"Group"
				["id"] = 123456789, -- Creator Id
			},
			["universe"] = {
				["spoof"] = true, -- Enable universe id spoof
				["id"] = 123456789, -- Universe Id
			},
			["place"] = {
				["spoof"] = true, -- Enable place id spoof
				["id"] = 123456789, -- Universe Id
			},
			["services"] = {
				-- Table with the services that will be spoofed using the 'game' hook.
				-- Automatically populated with built-in spoofs like httpservice, runservice, etc. if enabled
				-- Custom or other services can be supported by adding to this table: [className] = userdata or [instance] = userdata
			},
		},
		["httpservice"] = {
			["spoof"] = true, -- Spoofs game's HttpService with a custom version, 'game' hook must be enabled
			["httpenabled"] = true, -- Spoofs HttpEnabled with the desired value, use nil to keep the original value
		},
		["runservice"] = {
			["spoof"] = true, -- Spoofs game's RunService with a custom version, 'game' hook must be enabled
			["isstudio"] = true, -- Spoofs IsStudio with the desired value, use nil to keep the original value
		},
		["marketplaceservice"] = {
			["spoof"] = true, -- Spoofs game's MarketplaceService with a custom version, 'game' hook must be enabled
			["check"] = true, -- Before spoofing ownership status, it calls the original API and throws any errors to replicate behavior
			["gamepasses"] = { -- Spoofs MarketplaceService's UserOwnsGamePassAsync calls to return custom ownership statuses for specific passes and users
				--[[
				{
					userid = 000000000;
					gamepassid = 000000000;
					owns = true;
				};
			]]
			},
			-- !NOTE: Script can only use this with a valid Player, olssa checks that player's userid and spoofs if it matches
			["assets"] = { -- Spoofs MarketplaceService's UserOwnsGamePassAsync calls to return custom ownership statuses for specific passes and users
				--[[
				{
					userid = 000000000;
					assetid = 000000000;
					owns = true;
				};
			]]
			},
		},

		-- !NOTE: Instead of sandboxing by setting the fenv and iterating, just wrap the modulescript result
		-- (and edit wrapper to automatically return custom env values), tell wrapper it is a modulescript so it changes the tostring
		-- of getfenv to another random table value that is different
	}

	-- § Internally used globals
	local __script = script
	local __game = game
	local __workspace = workspace

	local __type = type
	local __typeof = typeof
	local __tostring = tostring
	local __debug = debug

	local __os = os
	local __os_clock = os.clock
	local __wait = wait

	local __tick = tick
	local __time = time

	local __task = task
	local __task_wait = task.wait
	local __task_delay = task.delay
	local __task_spawn = task.spawn
	local __DateTime = DateTime

	if __config.environment.custom.env ~= nil then
		__env = __config.environment.custom.env
	end
	local __gameservices = __config.game.services

	local function _env_write(k: string, v: any, o: any?)
		local clean = _rawget(__env, k)
		-- !NOTE: If original_value is nil, instead of using rawset, we'll add the new global to a table that will be indexed in a wrapped (maybe lighter than olssa wrap) environment
		-- Store original value under global name for potential restoration
		__globals.original[k] = if clean ~= nil then clean else o
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
	local __identifier = string.format(
		"%%%04x%04x%04x%04x%%",
		math.random(0, 0xFFFF),
		math.random(0, 0xFFFF),
		math.random(0, 0xFFFF),
		math.random(0, 0xFFFF)
	)
	local __timestamp = -__os_clock() -- Redefined later with positive timestamp, negative timetamp is then an indicator of an error in OLSSA itself

	-- Assigns a custom tag to the OLSSA thread in the Developer Console for memory usage analysis
	__debug.setmemorycategory(string.format("%s - OLSSA %s %s", __script.Name, __config.meta.revision, __identifier))

	-- § Logging
	-- § Logging
	local RunService = game:GetService("RunService")
	local logQueue = {}
	local queueConnection = nil

	-- Processing function moved outside for reuse
	local function processStackTrace(trace)
		local stack = {}
		local traceLines = trace:split("\n")

		for i = #traceLines, 1, -1 do
			local line = traceLines[i]:gsub("^%s+", ""):gsub("%s+$", "")
			if line == "" then
				continue
			end

			local fullname, number = line:match("^(.+):(%d+)")
			local func = line:match("function%s(.+)$")

			if not number then
				continue
			end

			local name = fullname and fullname:gsub(__script:GetFullName(), "(script)") or "(main)"
			local entry = func and string.format("%s.%s:%s", name, func, number)
				or string.format("%s:%s", name, number)

			table.insert(stack, entry)
		end

		return "| Stack Begin >  " .. table.concat(stack, " → ") .. "  < Stack End |"
	end

	local function processJob(job)
		-- Process arguments with dumping
		local dump = {}
		for i, v in ipairs(job.args) do
			if __config.logs.verbose >= 4 then
				local function __dump(val, indent, visited)
					-- Original dump implementation
					indent = indent or 0
					visited = visited or {}
					local ty = type(val)

					if ty == "table" then
						if visited[val] then return "<cyclic table>" end
						if val == getfenv() then return "<base env>" end
						visited[val] = true

						local parts = { string.rep("  ", indent) .. "{" }
						for k, v in pairs(val) do
							local keyStr = tostring(k)
							local valueStr = __dump(v, indent + 1, visited)
							table.insert(
								parts,
								string.rep("  ", indent + 1) .. "|→ " .. keyStr .. ": " .. valueStr
							)
						end
						table.insert(parts, string.rep("  ", indent) .. "}")
						return table.concat(parts, "\n")
					elseif ty == "function" then
						local name = debug.info(v, "n") or "anon"
						local nargs = debug.info(v, "a")
						local addr = tostring(v):match("(0x%x+)$") or "0x----"
						return string.format("ƒ[%s](%d) @%s", name, nargs, addr)
					elseif ty == "string" then
						return string.format("%q", val)
					else
						return tostring(val)
					end
				end
				dump[i] = __dump(v, 0, {})
			else
				dump[i] = tostring(v)
			end
		end

		local content = table.concat(dump, ", ")

		-- Content filtering
		if __config.logs.whitelist and not content:match(__config.logs.whitelist) then
			return
		end
		if __config.logs.blacklist and content:match(__config.logs.blacklist) then
			return
		end

		-- Final output
		local message = table.concat({ job.header, content, __identifier }, " :: ")
		local indent = string.rep(" ", 16)
		warn(message, "\n" .. indent .. job.stacktrace)
	end

	local function onHeartbeat()
		local start = os.clock()
		while #logQueue > 0 and (os.clock() - start) < 0.016 do -- 16ms budget
			processJob(table.remove(logQueue, 1))
		end
		if #logQueue == 0 and queueConnection then
			queueConnection:Disconnect()
			queueConnection = nil
		end
	end

	local function enqueueJob(job)
		table.insert(logQueue, job)
		if not queueConnection then
			queueConnection = RunService.Heartbeat:Connect(onHeartbeat)
		end
	end

	local _log = __config.logs.verbose > 0
		and function(level: number, ...: any)
			if level > __config.logs.verbose then return end
			if math.sign(__timestamp) ~= 1 and not __config.logs.prelogs then return end

			-- Capture time-sensitive data first
			local timestamp = math.sign(__timestamp) * math.round((os.clock() - math.abs(__timestamp)) * 1000)
			local header = ("[OLSSA] %s (l%d %dms)"):format(
				__script:GetFullName(),
				level,
				timestamp
			)
			local trace = processStackTrace(debug.traceback())

			enqueueJob({
				level = level,
				header = header,
				args = { ... },
				stacktrace = trace,
				timestamp = timestamp
			})
		end
		or function() end

	local function _async_log(...)
		return _log(...)--task.spawn(_log, ...)
	end

	-- § Wrapper
	local _wrapper = (function()
		local self = {}

		-- Weak cache tables with string-based keys for security
		local __cache = {
			original = _setmetatable({}, { __mode = "k" }),
			wrapped = _setmetatable({}, { __mode = "k" }),
		}

		-- During configuration initialization
		local __blacklist = {
			keys = _setmetatable({}, { __mode = "k" }),
			values = _setmetatable({}, { __mode = "v" }),
		}

		-- Convert array blacklists to hash tables once during init
		for _, k in ipairs(__config.wrapper.blacklist.keys) do
			__blacklist.keys[k] = true
		end

		for _, v in ipairs(__config.wrapper.blacklist.values) do
			__blacklist.values[v] = true
		end

		local function get_game_service(k, v)
			-- Given either a key, value, or both, return the corresponding custom game service
			if not v and __typeof(k) ~= "string" then
				return nil
			end

			v = self:unwrap(v)

			if __typeof(v) == "Instance" then
				return __gameservices[v.ClassName] or __gameservices[v]
			end

			return self:wrap(__gameservices[k] or __gameservices[v], nil, false, false, false, true)
		end

		-- Core wrapper method with security hardening
		function self:wrap(
			obj: any,
			cnt: {}?,
			light: boolean?,
			usekeys: boolean?,
			isenv: boolean?,
			isgame: boolean?
		): any
			if obj == nil then
				return nil
			end

			obj = self:unwrap(obj)

			if __cache.wrapped[obj] then
				return __cache.wrapped[obj]
			end

			if obj == __env then
				isenv = true
			end

			local obj_type = __type(obj)

			if obj == __game then
				isgame = true
			end
			local prefix = if isenv then "ENV" else (if obj == __game then "GAME" else string.upper(obj_type)) -- isgame condition also applies to nested methods so we can't use it

			-- Userdata proxy with native behavior preservation
			if obj_type == "userdata" then
				local wrapped = newproxy(true)
				local meta = _getmetatable(wrapped)
				meta.__index = function(_, k)
					local raw_value = obj[k]

					_async_log(3, prefix .. "_GET", obj, k, raw_value)

					if __config.wrapper.blacklist.enabled then
						if (__blacklist.keys[k] ~= nil) or (__blacklist.values[raw_value] ~= nil) then
							_async_log(3, prefix .. "_RAW_VALUE", obj, k, raw_value)
							return raw_value
						end
					end

					-- If we're indexing a global that we're spoofing, return it
					local spoofed_value = cnt and cnt[k]
					if spoofed_value ~= nil then
						_async_log(3, prefix .. "_VALUE_SPOOF", obj, k, spoofed_value)
						return self:wrap(spoofed_value)
					end

					-- Userdata is wrapped game
					if isgame then
						-- If we're indexing a game service that we're spoofing, return it
						local spoofed_service = get_game_service(k, raw_value)
						if spoofed_service ~= nil then
							_async_log(3, prefix .. "_SERVICE_SPOOF", obj, k, spoofed_service)
							return self:wrap(spoofed_service, nil, light, nil, nil, isgame)
						end
					end

					-- If we're indexing a global (or index points to original global) that we're spoofing, return the spoofed version
					local spoofed_global = if usekeys
						then __globals.custom[k]
						else __globals.custom[self:unwrap(raw_value)]
					if spoofed_global ~= nil then
						_async_log(isenv and 4 or 3, prefix .. "_GLOBAL_SPOOF", obj, k, spoofed_global)
						return self:wrap(spoofed_global)
					end

					if light then
						return raw_value
					end

					return self:wrap(raw_value, nil, false, false, false, isgame)
				end

				meta.__newindex = function(_, k: string, v: any)
					_async_log(3, prefix .. "_SET", obj, k, v)
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

						local prefix = if isenv then "ENV" else "TABLE"
						_async_log(3, prefix .. "_GET", obj, k, raw_value)

						if __config.wrapper.blacklist.enabled then
							if (__blacklist.keys[k] ~= nil) or (__blacklist.values[raw_value] ~= nil) then
								_async_log(3, prefix .. "_RAW_VALUE", obj, k, raw_value)
								return raw_value
							end
						end

						-- If we're indexing a global that we're spoofing, return it
						local spoofed_value = cnt and cnt[k]
						if spoofed_value ~= nil then
							_async_log(3, prefix .. "_VALUE_SPOOF", obj, k, spoofed_value)
							return self:wrap(spoofed_value)
						end

						-- Table comes from game (i.e. getchildren)
						if isgame then
							-- If we're indexing a game service that we're spoofing, return it
							local spoofed_service = get_game_service(k, raw_value)
							if spoofed_service ~= nil then
								_async_log(3, "GAME_SERVICE_SPOOF", obj, k, spoofed_service)
								return self:wrap(spoofed_service, nil, light, false, false, isgame)
							end
						end

						-- If we're indexing a global (or index points to original global) that we're spoofing, return the spoofed version
						local spoofed_global = if usekeys
							then __globals.custom[k]
							else __globals.custom[self:unwrap(raw_value)]
						if spoofed_global ~= nil then
							_async_log(isenv and 4 or 3, prefix .. "_GLOBAL_SPOOF", obj, k, spoofed_global)
							return self:wrap(spoofed_global)
						end

						if light then
							return raw_value
						end

						return self:wrap(raw_value)
					end,

					__newindex = function(_, k: any, v: any)
						_async_log(3, prefix .. "_SET", obj, k)
						obj[k] = self:unwrap(v)
					end,

					__iter = function()
						local next_fn, state, init = pairs(obj)
						return function()
							local k, v = next_fn(state, init)
							init = k
							return self:wrap(k), self:wrap(v)
						end
					end,

					__tostring = function()
						return tostring(obj)
					end,

					__metatable = _getmetatable(obj),
				})
				return wrapped

			-- Function wrapper with call monitoring
			elseif obj_type == "function" then
				_async_log(4, "WRAP_FUNCTION", obj)
				local wrapped = function(...: any): ...any
					_async_log(4, "CALL_FUNCTION", obj, ...)
					local args = { ... }
					for i = 1, _select("#", ...) do
						args[i] = self:unwrap(args[i])
					end

					local success, results = pcall(obj, _unpack(args))
					if not success then
						error(results, 2)
					end

					results = { results }

					-- Result comes from game func (i.e. getservice)
					if isgame then
						-- If we're indexing a game service that we're spoofing, return it
						for i = 1, #results do
							local spoofed_service = get_game_service(nil, results[i])
							if spoofed_service ~= nil then
								_async_log(3, "GAME_SERVICE_SPOOF", obj, results[i].ClassName, spoofed_service)
								results[i] = spoofed_service
							end
						end
					end

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
	_env_write(
		"require",
		_wrapper:wrap(function(v: ModuleScript | any?)
			if __type(v) == "number" then
				-- Require has been called with an AssetId
				_log(1, "REQUIRE_EXT", v)
				if __config.require.spoof then
					local mobj = __config.require:lookup(v)
					if mobj ~= nil then
						_log(2, "REQUIRE_SPOOF", v, mobj.Name)
						-- emulate external require call stack?
						-- replicate mainmodule hierarchy: nil --> Model required_asset_{v} --> ModuleScript MainModule
						-- clone mobj? rename it MainModule and put inside required asset module?
						-- add to a lookup table for wrapper so that when mainmodule name or parent is indexed pass correct info
						if __config.require.mock then
							local model = Instance.new("Model")
							model.Parent = nil -- model gets garbage collected, try wrapping instead of this
							model.Name = string.format("required_asset_%d", v)
							mobj = mobj:Clone()
							mobj.Parent = model
							mobj.Name = "MainModule"
						end
						v = mobj
					else
						_log(2, "REQUIRE_RAW", v)
					end
				end
			else
				if __typeof(v) == "Instance" then
					-- Require has been called with a local modulescript
					_log(1, "REQUIRE_INT", v:GetFullName())
				else
					-- Require has been called with an unknown value type
					_log(1, "REQUIRE_UNK", __type(v), __typeof(v), v)
				end
			end
			local o = __require(v)
			_log(1, "REQUIRE_DATA", { o })
			return o
		end),
		__require
	)

	-- § 'HttpService' Traffic Hook & Enabled Spoof
	-- § 'MarketplaceService' Select-product ownership Spoof
	-- § 'DatastoreService' Traffic Hook

	-- § 'game' Hook & Spoofs
	if __config.game.hook then
		_env_write(
			"game",
			_wrapper:wrap(__game, {
				CreatorId = if __config.game.creator.spoof then __config.game.creator.id else __game.CreatorId,
				CreatorType = if __config.game.creator.spoof
					then Enum.CreatorType:FromName(__config.game.creator.type)
					else __game.CreatorType,
				GameId = if __config.game.universe.spoof then __config.game.universe.id else __game.GameId,
				PlaceId = if __config.game.place.spoof then __config.game.place.id else __game.PlaceId,
			}),
			__game
		)
	end

	-- § OS Clock, Tick, Time Compression
	if __config.time.hook then
		do
			-- Save original timing functions
			-- Internal state for os.clock spoofing
			local fakeTime: number = __os_clock()
			local lastReal: number = __os_clock()

			_env_write(
				"os",
				_wrapper:wrap(__os, {
					["clock"] = function(): number
						local now: number = __os_clock()
						local dt: number = now - lastReal
						fakeTime = fakeTime + dt * __config.time.dilation
						lastReal = now
						return fakeTime
					end,
				}),
				__os
			)

			_env_write("wait", function(...: any): any
				local ret = __wait(...)
				local now: number = __os_clock()
				fakeTime = math.max(fakeTime, now)
				lastReal = now
				return ret
			end, __wait)

			_env_write(
				"task",
				_wrapper:wrap(__task, {
					["wait"] = function(...: any): any
						local ret = __task_wait(...)
						local now: number = __os_clock()
						fakeTime = math.max(fakeTime, now)
						lastReal = now
						return ret
					end,
					["delay"] = function(delay: number, callback: (...any) -> (), ...: any): ()
						local args: { any } = { ... }
						local function wrappedCallback(...: any)
							local now: number = __os_clock()
							fakeTime = math.max(fakeTime, now)
							lastReal = now
							callback(...)
						end
						return __task_delay(delay, wrappedCallback, table.unpack(args))
					end,
				}),
				__task
			)
		end
		do
			-- Internal state for tick spoofing.
			local fakeTickTime: number = __tick()
			local lastRealTick: number = __tick()

			--- Fake tick that returns a dilated value
			local function tick(): number
				local now: number = __tick()
				local dt: number = now - lastRealTick
				fakeTickTime = fakeTickTime + dt * __config.time.dilation
				lastRealTick = now
				return fakeTickTime
			end

			--- Fake time returns the integer part of fake_tick

			_env_write("tick", tick, __tick)
			_env_write("time", function(): number
				return math.floor(tick())
			end, __time)

			-- Override DateTime.now to use fake_tick as well
			_env_write(
				"DateTime",
				_wrapper:wrap(DateTime, {
					["now"] = function(): DateTime
						return __DateTime.fromUnixTimestamp(tick())
					end,
				}),
				__DateTime
			)
		end
	end
	--_env_write("workspace", _wrapper:wrap(workspace))
	--_env_write("print", _wrapper:wrap(print))

	-- § Wrap environment
	if __config.environment.wrap then
		_setfenv(1, _wrapper:wrap(__env, nil, __config.environment.light, __config.environment.usekeys))
	end

	__debug.resetmemorycategory() -- Reset thread developer console tag
	__timestamp = __os_clock() -- Reset timestam
end -- ⚠️ OLSSA Auditor Snippet End ⚠️
--================----===OLSSAEND===----================--

local start = os.clock()
--for i = 1, 1e6 do
--	game:GetService("Workspace")
--end
print("Wrapped access time:", os.clock() - start) -- Target <0.1s

--print(rawget(getfenv(), "require"), require, rawget(getfenv(), "game"), game.CreatorId, workspace.Parent.CreatorId)
--print(require(script.Parent["OLDolssa.rewrite copy"]))
--print('\'func is ' .. (pcall(setfenv, rawset, getfenv(rawset)) and 'Lua' or 'C'))
--print(require(145458))
print(
	getmetatable(getfenv()),
	rawget(getfenv(), "game"),
	typeof(game),
	game.CreatorId,
	workspace.Parent.CreatorId,
	game == workspace.Baseplate.Parent.Parent,
	tostring(game),
	getmetatable(game)
)
print(
	game:FindFirstChild("ServerScriptService"),
	game.ServerScriptService,
	game:GetService("ServerScriptService"),
	game:FindService("ServerScriptService")
)
print(game.ServerScriptService.Parent.CreatorId)
