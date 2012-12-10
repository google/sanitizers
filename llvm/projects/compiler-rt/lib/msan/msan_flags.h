namespace __msan {

// Flags.
struct Flags {
  int exit_code;
  int num_callers;
  int verbosity;
  bool poison_heap_with_zeroes;  // default: false
  bool poison_stack_with_zeroes;  // default: false
  bool poison_in_malloc;  // default: true
  bool report_umrs;
};

Flags *flags();

}  // namespace __msan
