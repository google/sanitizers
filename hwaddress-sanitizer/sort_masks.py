masks = [0,   1,   2,   3,   4,   6,   7,   8,   12,  14,  15, 16,  24,
         28,  30,  31,  32,  48,  56,  60,  62,  63,  64,  96, 112, 120,
         124, 126, 127, 128, 192, 224, 240, 248, 252, 254]

new_masks = [0]

for i in range(0, 35):
  lowest_num_collisions = None
  next_mask = None
  for m1 in masks:
    if m1 in new_masks:
      continue
    num_collisions = 0
    for m2 in new_masks:
      for cur in range(0, 256):
        for next in range(cur + 1, cur + 128):
          if cur ^ m1 == (next & 255) ^ m2:
            # Assume that the probability of a bug decreases exponentially
            # with temporal distance.
            num_collisions += 1. / pow(2, next - cur)
    if lowest_num_collisions is None or num_collisions < lowest_num_collisions:
      lowest_num_collisions = num_collisions
      next_mask = m1
  new_masks += [next_mask]

print new_masks
