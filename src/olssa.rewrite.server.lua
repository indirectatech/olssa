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
	--!NOTE: DO NOT declare globals anywhere; Declare local variables ONLY INSIDE THE DO, otherwise it will be accessible to code below auditor

	 -- Base Environment & Original Globals
	local __env = getfenv()

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
	};


	-- Generate a unique OLSSA-session identifier, which can be used to string match logs (and hide them if hooking LogService)
	-- __identifier --> "%451676bcada921d7%"
	local __identifier = string.format("%%%04x%04x%04x%04x%%", math.random(0, 0xFFFF), math.random(0, 0xFFFF), math.random(0, 0xFFFF), math.random(0, 0xFFFF));
	local __timestamp = -os.clock(); -- Redefined later with positive timestamp, negative timetamp is then an indicator of an error in OLSSA itself

	-- Assigns a custom tag to the OLSSA thread in the Developer Console for memory usage analysis
	debug.setmemorycategory(string.format("%s - OLSSA %s %s", script.Name, __config.meta.revision, __identifier))


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
	
				local name = fullname:match("[^%.]+$") or "Unknown"
				local entry = func and string.format("%s.%s:%s", name, func, number)
							  or string.format("%s:%s", name, number)
				
				table.insert(stack, entry)
			end
			
			return "| Stack Begin >  " .. table.concat(stack, " → ") .. "  < Stack End |"
		end
		
			
		local timestamp = math.sign(__timestamp) * math.round((os.clock() - math.abs(__timestamp)) * 1000)
		local indent = string.rep(" ", 16)

		-- Build message components
		local messageParts = {
			string.format("OLSSA %s (l%d %dms)", script.Name, level, timestamp),
			table.concat({...}, ", "),
			__identifier
		}
		
		-- Format final output
		local fullMessage = table.concat(messageParts, " :: ")
		local stackTrace = processStackTrace(debug.traceback())
		
		warn(fullMessage, "\n" .. indent .. stackTrace)
	end;

	_log(1, "test lol wow")
	local function test()
		_log(1, "test2 lol wow")

	end
	test()
	
	debug.resetmemorycategory() -- Reset thread developer console tag
	__timestamp = os.clock(); -- Reset timestam
end -- ⚠️ OLSSA Auditor Snippet End ⚠️

