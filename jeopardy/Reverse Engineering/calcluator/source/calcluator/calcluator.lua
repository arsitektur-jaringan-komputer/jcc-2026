-- calculator.lua
-- Lua 5.1 / LuaJIT compatible

local MOD = 65521


local function bxor(a, b)
    local r = 0
    local p = 1

    while a > 0 or b > 0 do
        local x = a % 2
        local y = b % 2

        if x ~= y then
            r = r + p
        end

        a = math.floor(a / 2)
        b = math.floor(b / 2)
        p = p * 2
    end

    return r
end


local target_blob = "5765712076b155dcbe21fde9"


local encrypted = "479d34633443c69c19b5002c1c2ecc66b858745aa2ab15051ae741cf5a5e0f07c10b23ccce6014fc6716c69268d74e"


local tags = {
    ["+"] = 17,
    ["-"] = 29,
    ["*"] = 43,
    ["/"] = 61,
    ["%"] = 79
}


local ans = 0
local state = 0x1337
local step = 0
local bad = 0
local history = {}


local function get_target(i)
    local p = (i - 1) * 4 + 1

    if p + 3 > #target_blob then
        return nil
    end

    local lo = tonumber(
        target_blob:sub(p, p + 1),
        16
    )

    local hi = tonumber(
        target_blob:sub(p + 2, p + 3),
        16
    )

    return lo + hi * 256
end


local function reset()
    ans = 0
    state = 0x1337
    step = 0
    bad = 0
    history = {}
end


local function calculate(op, value)
    local before = ans
    local result


    if op == "+" then

        result = before + value


    elseif op == "-" then

        result = before - value


    elseif op == "*" then

        result = before * value


    elseif op == "/" then

        if value == 0 then
            return nil, "division by zero"
        end

        if before % value ~= 0 then
            return nil, "non-exact division"
        end

        result = before / value


    elseif op == "%" then

        if value == 0 then
            return nil, "modulo by zero"
        end

        result = before % value


    else

        return nil, "unknown operator"
    end


    step = step + 1

    local tag = tags[op]


    local x = (
        value
        + tag * 257
        + step * 911
        + (before % MOD) * 13
    ) % MOD


    local sig = (
        x * 251
        + (result % MOD) * 17
        + state
    ) % MOD


    local expected = get_target(step)

    if expected == nil or sig ~= expected then
        bad = bad + 1
    end


    state = (
        state * 109
        + sig * 97
        + tag * 31
        + step * 7
    ) % MOD


    ans = result


    history[#history + 1] =
        tostring(before)
        .. " "
        .. op
        .. " "
        .. tostring(value)
        .. " = "
        .. tostring(result)


    return result
end

local function hexbyte(s, i)
    return tonumber(
        s:sub(i, i + 1),
        16
    )
end

local function decrypt()
    if step ~= 6 then
        return nil
    end

    if bad ~= 0 then
        return nil
    end


    local seed = (
        state
        + (ans % 256) * 257
        + 0x5A
    ) % 256


    local out = {}


    local count = #encrypted / 2

    for i = 1, count do
        seed = (
            seed * 73
            + 41
        ) % 256

        local p = (i - 1) * 2 + 1
        local c = hexbyte(encrypted, p)

        out[i] = string.char(
            bxor(c, seed)
        )
    end


    return table.concat(out)
end


local function show_help()
    print("")
    print("LuaCalc 1.5")
    print("----------------------")
    print("Operations:")
    print("  + N")
    print("  - N")
    print("  * N")
    print("  / N")
    print("  % N")
    print("")
    print("Commands:")
    print("  ans")
    print("  history")
    print("  clear")
    print("  help")
    print("  quit")
    print("")
end


local function show_history()
    if #history == 0 then
        print("(empty)")
        return
    end

    for i = 1, #history do
        print(
            string.format(
                "%02d: %s",
                i,
                history[i]
            )
        )
    end
end


local diagnostic =
    string.char(100, 105, 97, 103)


print("")
print("LuaCalc 1.5")
print("Simple Integer Calculator")
print("Type 'help' for commands.")
print("")


while true do
    io.write("> ")

    local line = io.read("*l")

    if not line then
        break
    end


    line = line:match("^%s*(.-)%s*$")


    if line == "quit" then

        break


    elseif line == "help" then

        show_help()


    elseif line == "ans" then

        print(ans)


    elseif line == "history" then

        show_history()


    elseif line == "clear" then

        reset()
        print("0")


    elseif line == diagnostic then

        local flag = decrypt()

        if flag then
            print("Diagnostic OK")
            print(flag)
        else
            print("Diagnostic failed")
        end


    else

        local op, raw =
            line:match(
                "^%s*(.)%s*(%d+)%s*$"
            )


        if not op or not tags[op] then

            print("syntax error")


        else

            local value = tonumber(raw)


            if not value
                or value < 0
                or value > 255 then

                print(
                    "operand must be between 0 and 255"
                )


            else

                local result, err =
                    calculate(op, value)


                if result == nil then
                    print(err)
                else
                    print(result)
                end

            end
        end
    end
end
