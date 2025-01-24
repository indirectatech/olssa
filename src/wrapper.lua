

local __wrapper_cache = setmetatable({}, {__mode = "k"})
local __wrapper_func_wraps = setmetatable({}, {__mode = "k"}) -- Separate cache for function wraps
local __wrapper_protected_keys = {
    -- Add security-critical keys that should never be exposed
    "GetFullName", "GetChildren", "GetDescendants",
    "Clone", "Destroy", "InvokeServer", "FireServer"
}

-- Security enhancement: Dual-layer cache protection
local __wrapper_reverse_cache = setmetatable({}, {__mode = "v"})
local function __wrapper_cache_store(wrapped, real)
    __wrapper_cache[wrapped] = real
    __wrapper_reverse_cache[real] = wrapped
end

local function __wrapper_unwrap(wrapped)
    if type(wrapped) ~= "userdata" and type(wrapped) ~= "table" and type(wrapped) ~= "function" then
        return wrapped
    end
    return __wrapper_cache[wrapped] or wrapped
end

local function __wrapper_wrap(obj, data, depth)
    depth = depth or 0
    data = data or {}
    
    -- Security: Prevent infinite recursion
    if depth > 64 then
        warn("OLSSA: Maximum wrap depth exceeded")
        return obj
    end

    -- Check cache first
    local cached = __wrapper_reverse_cache[obj]
    if cached then
        return cached
    end

    local obj_type = __type(obj)
    local obj_typeof = __typeof(obj)

    -- Optimization: Memoize function wraps
    if obj_type == "function" and __wrapper_func_wraps[obj] then
        return __wrapper_func_wraps[obj]
    end

    -- Security: Validate object type before wrapping
    if obj_type == "userdata" and not pcall(function() return obj.ClassName end) then
        return obj
    end

    local fake
    if obj_type == "userdata" then
        fake = newproxy(true)
        local meta = getmetatable(fake)
        
        -- Security: Lock metatable
        meta.__metatable = "Locked Metatable - OLSSA Protected"
        
        meta.__index = function(_, k)

            local raw_val = obj[k]
            
            -- Security: Validate core services
            if k == "Parent" and __config.WRAPPED_PARENT_SPOOF_SEC then
				for _g, _v in __globals do
					if raw_val == _v then return rawget(__env, _g) end;
				end
                --if raw_val == __game then return __env.game end
                --if raw_val == __workspace then return __env.workspace end
                --if raw_val == __script then return __env.script end
            end
            
            -- Optimization: Direct return for primitive types
            local val_type = __type(raw_val)
            if val_type ~= "userdata" and val_type ~= "table" and val_type ~= "function" then
                return raw_val
            end
            
            return __wrapper_wrap(raw_val, nil, depth + 1)
        end

        meta.__newindex = function(_, k, v)
            -- Security: Prevent modification of critical properties
            if table.find(__wrapper_protected_keys, k) then
                --error("OLSSA: Attempt to modify protected key: "..tostring(k), 2)
				return
            end
            
            -- Security: Unwrap values before assignment
            obj[k] = __wrapper_unwrap(v)
        end

        meta.__tostring = function()
            return tostring(obj) -- Preserve original string representation
        end

        __wrapper_cache_store(fake, obj)

    elseif obj_type == "table" then
        -- Optimization: Use table.create for better performance
        fake = table.create(#obj)
        for k, v in pairs(obj) do
            local unwrapped_k = __wrapper_unwrap(k)
            fake[unwrapped_k] = __wrapper_wrap(v, nil, depth + 1)
        end
        
        -- Security: Protect table metatable
        setmetatable(fake, {
            __metatable = nil,
            __index = function(_, k)
                return __wrapper_wrap(rawget(obj, k), nil, depth + 1)
            end,
            __newindex = function(t, k, v)
                rawset(obj, k, __wrapper_unwrap(v))
            end
        })
        
    elseif obj_type == "function" then
        -- Optimization: Memoize function wraps
        if __wrapper_func_wraps[obj] then
            return __wrapper_func_wraps[obj]
        end
        
        fake = function(...)
            local args = table.create(select("#", ...))
            for i = 1, select("#", ...) do
                args[i] = __wrapper_unwrap(select(i, ...))
            end
            
            local results = table.pack(obj(unpack(args)))
            for i = 1, results.n do
                results[i] = __wrapper_wrap(results[i], nil, depth + 1)
            end
            
            return unpack(results, 1, results.n)
        end
        
        __wrapper_func_wraps[obj] = fake
        __wrapper_cache_store(fake, obj)
    else
        return obj
    end

    return fake
end
