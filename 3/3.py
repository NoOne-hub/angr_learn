import angr
import claripy
import sys

def main(argv):
  path_to_binary = "./angr_3_test"
  project = angr.Project(path_to_binary)

  start_address = 0x80495D0  # address right after the get_input function call
  initial_state = project.factory.blank_state(addr=start_address)

  password_size_in_bits = 32
  password0 = claripy.BVS('password0', password_size_in_bits)
  password1 = claripy.BVS('password1', password_size_in_bits)
  password2 = claripy.BVS('password2', password_size_in_bits)

  initial_state.regs.eax = password0
  initial_state.regs.ebx = password1
  initial_state.regs.edx = password2

  simulation = project.factory.simgr(initial_state) 

  def is_successful(state):
    stdout_output = state.posix.dumps(sys.stdout.fileno())
    print(stdout_output)
    if b'Good Job.\n' in stdout_output:
      return True
    else: return False

  def should_abort(state):
    stdout_output = state.posix.dumps(sys.stdout.fileno())
    if b'Try again.\n' in  stdout_output:
      return True
    else: return False 

  simulation.explore(find=is_successful, avoid=should_abort)

  if simulation.found:
    solution_state = simulation.found[0]

    solution0 = format(solution_state.solver.eval(password0), 'x')
    solution1 = format(solution_state.solver.eval(password1), 'x')
    solution2 = format(solution_state.solver.eval(password2), 'x')

    solution = solution0 + " " + solution1 + " " + solution2  # :string
    print("[+] Success! Solution is: {}".format(solution))
  else:
    raise Exception('Could not find the solution')

if __name__ == '__main__':
  main(sys.argv)