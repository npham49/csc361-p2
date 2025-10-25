import sys
import main

def run_main_with_args():
    """
    Runs main.py as a module and passes the first argument from Tracer.py
    """
    if len(sys.argv) > 1:
        first_arg = sys.argv[1]
        
        original_argv = sys.argv.copy()
        sys.argv = ['main.py', first_arg]
        
        try:
            main.main()
        finally:
            sys.argv = original_argv
    else:
        print("No arguments provided to Tracer.py")

if __name__ == "__main__":
    run_main_with_args()
