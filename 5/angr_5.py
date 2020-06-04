import angr
import sys
import claripy

binary = './angr_5'
start = 0x1307
good = (0x137C)
bad = (0x1368)



input = 0x47C580-0x4000
    
p = angr.Project(binary, load_options={'main_opts': {'custom_base_addr': 0, 'auto_load_lib':False}})
state = p.factory.blank_state(addr=start)
bits = 64
password0 = claripy.BVS('password0', bits)
password1 = claripy.BVS('password1', bits)
password2 = claripy.BVS('password2', bits)
password3 = claripy.BVS('password3', bits)

state.memory.store(input, password0)
state.memory.store(input+8, password1)
state.memory.store(input+0x10, password2)
state.memory.store(input+0x18, password3)



simulation = p.factory.simgr(state)
simulation.explore(find=good, avoid=bad)
if simulation.found:
    solution_state = simulation.found[0]
    solution0 = solution_state.solver.eval(password0, cast_to=bytes)
    solution1 = solution_state.solver.eval(password1, cast_to=bytes)
    solution2 = solution_state.solver.eval(password2, cast_to=bytes)
    solution3 = solution_state.solver.eval(password3, cast_to=bytes)
    
    print(solution0,solution1, solution2, solution3)
else:
    raise Exception("Could not find the solution")


