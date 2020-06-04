import angr
import sys
import claripy

binary = './angr_3'
start = 0x4015BD
good = (0x401621)
bad = (0x40160B)

def is_good(state):
    return b'Good Job' in state.posix.dumps(sys.stdout.fileno())
def is_bad(state):
    return b'Try again' in state.posix.dumps(sys.stdout.fileno())
    
p = angr.Project(binary)
state = p.factory.blank_state(addr=start)
bits = 32
pass0 = claripy.BVS('pass0', bits)
pass1 = claripy.BVS('pass1', bits)
pass2 = claripy.BVS('pass2', bits)
state.regs.eax = pass0
state.regs.ebx = pass1
state.regs.edx = pass2



simulation = p.factory.simgr(state)
print(simulation.deadended)
simulation.explore(find=is_good, avoid=is_bad)

if simulation.found:
    solution_state = simulation.found[0]
    solution0 = solution_state.se.eval(password0)
    solution1 = solution_state.se.eval(password1)
    solution2 = solution_state.se.eval(password2)
    solution = ' '.join(map('{:x}'.format, [ solution0, solution1, solution2]))
    print(solution)
else:
    raise Exception("Could not find the solution")


