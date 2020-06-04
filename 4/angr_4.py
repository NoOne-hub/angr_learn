import angr
import sys
import claripy

binary = './angr_4'
start = 0x4013FB
good = (0x401447)
bad = (0x401433)

def is_good(state):
    print(state.posix.dumps(1))
    return b'Good Job' in state.posix.dumps(sys.stdout.fileno())
def is_bad(state):
    print(state.posix.dumps(1))
    return b'Try again' in state.posix.dumps(sys.stdout.fileno())
    
p = angr.Project(binary)
state = p.factory.blank_state(addr=start)
state.stack_push(state.regs.ebp)
state.regs.ebp = state.regs.esp
state.regs.esp -= 0x8

bits = 32
password0 = claripy.BVS('password0', bits)
password1 = claripy.BVS('password1', bits)
state.stack_push(password0)
state.stack_push(password1)


simulation = p.factory.simgr(state)
simulation.explore(find=good, avoid=bad)
if simulation.found:
    solution_state = simulation.found[0]
    solution0 = solution_state.se.eval(password0)
    solution1 = solution_state.se.eval(password1)
    solution = ' '.join(map('{:}'.format, [ solution0, solution1]))
    print(solution)
else:
    raise Exception("Could not find the solution")


