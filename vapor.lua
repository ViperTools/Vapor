---@diagnostic disable: undefined-global

-- Process
local process = Process(name)
local process = Process(id)

-- Memory
local memory = Memory(process)

memory:Read(address, len)
memory:ReadInt(address)
memory:ReadFloat(address)
memory:ReadString(address)