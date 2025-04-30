# Function to represent moving a disk and print the action
def move_disk(disk_num, from_peg, to_peg, pegs):
  """Simulates moving a disk, updates peg state, and prints the move."""
  disk = pegs[from_peg].pop()
  if disk != disk_num:
      # Basic sanity check, should match the disk we expect to move
      print(f"Error: Trying to move disk {disk_num} but found disk {disk}")
      # Put it back for safety in this example, though ideally handle error
      pegs[from_peg].append(disk)
      return

  # Basic validation: Ensure we don't put a larger disk on a smaller one
  if pegs[to_peg] and pegs[to_peg][-1] < disk:
      print(f"Error: Cannot place disk {disk} on smaller disk {pegs[to_peg][-1]}")
      # Put it back for safety
      pegs[from_peg].append(disk)
      return

  pegs[to_peg].append(disk)
  print(f"Move disk {disk_num} from {from_peg} to {to_peg}")
  # Optional: print state of pegs after move
  # print(pegs)

# Recursive function for Tower of Hanoi
def tower_of_hanoi(n, source_peg, target_peg, auxiliary_peg, pegs):
  """
  Solves the Tower of Hanoi problem recursively.

  Args:
    n: The number of top disks to move.
    source_peg: The name of the source peg.
    target_peg: The name of the target peg.
    auxiliary_peg: The name of the auxiliary peg.
    pegs: A dictionary representing the pegs and the disks on them.
          Example: {'A': [3, 2, 1], 'B': [], 'C': []} where 1 is the smallest disk.
  """
  if n > 0:
    # Step 1: Move n-1 disks from source to auxiliary, using target as spare
    tower_of_hanoi(n - 1, source_peg, auxiliary_peg, target_peg, pegs)

    # Step 2: Move the nth disk (largest in this subproblem) from source to target
    # We identify the disk number based on the source peg's current top disk.
    # In a more robust implementation, you might pass the specific disk number.
    # For simplicity here, we assume the top disk IS the nth disk for this step.
    if pegs[source_peg]:
        disk_to_move = pegs[source_peg][-1] # Get the actual disk number/size
        move_disk(disk_to_move, source_peg, target_peg, pegs)
    else:
        print(f"Error: Source peg {source_peg} is empty when trying to move disk {n}")


    # Step 3: Move the n-1 disks from auxiliary to target, using source as spare
    tower_of_hanoi(n - 1, auxiliary_peg, target_peg, source_peg, pegs)

# --- Example Usage ---
num_disks = 3
peg_names = ['A', 'B', 'C']

# Initialize pegs: Disks represented by numbers (e.g., 3 is largest, 1 is smallest)
# Peg 'A' has disks [3, 2, 1] initially (bottom to top)
pegs_state = {
    peg_names[0]: list(range(num_disks, 0, -1)), # Source: e.g. [3, 2, 1]
    peg_names[1]: [],                           # Auxiliary
    peg_names[2]: []                            # Target
}

print("Initial state:", pegs_state)
tower_of_hanoi(num_disks, peg_names[0], peg_names[2], peg_names[1], pegs_state)
print("Final state:", pegs_state)
