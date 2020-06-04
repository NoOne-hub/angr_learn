import angr
import claripy
import sys
def main():
  path_to_binary = '05_angr_symbolic_memory'
  project = angr.Project(path_to_binary, load_options={'main_opts': {'custom_base_addr': 0, 'auto_load_lib':False}})

  start_address = 0x8048601
  initial_state = project.factory.blank_state(addr=start_address)

  password0 = claripy.BVS('password0', 8 * 8)
  password1 = claripy.BVS('password1', 8 * 8)
  password2 = claripy.BVS('password2', 8 * 8)
  password3 = claripy.BVS('password3', 8 * 8)

  password0_address = 0x9FD92A0
  initial_state.memory.store(password0_address, password0)
  password1_address = 0x9FD92A8
  initial_state.memory.store(password1_address, password1)
  password2_address = 0x9FD92B0
  initial_state.memory.store(password2_address, password2)
  password3_address = 0x9FD92B8
  initial_state.memory.store(password3_address, password3)

  simulation = project.factory.simgr(initial_state)

  def is_successful(state):
    stdout_output = state.posix.dumps(sys.stdout.fileno())
    return 'Good Job' in str(stdout_output)

  def should_abort(state):
    stdout_output = state.posix.dumps(sys.stdout.fileno())
    return 'Try again' in str(stdout_output)

  simulation.explore(find=is_successful, avoid=should_abort)

  if simulation.found:
    solution_state = simulation.found[0]
    solution0 = solution_state.solver.eval(password0)
    solution1 = solution_state.solver.eval(password1)
    solution2 = solution_state.solver.eval(password2)
    solution3 = solution_state.solver.eval(password3)
    solution = ' '.join(map('{:x}'.format, [ solution0, solution1,solution2,solution3 ]))

    print(solution)
    
if __name__ == '__main__':
    main()