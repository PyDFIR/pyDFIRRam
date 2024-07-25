import subprocess
import os

def build_submodule():
    submodule_path = os.path.join(os.path.dirname(__file__), './volatility3/')
    subprocess.check_call(['pip', 'install', '.'], cwd=submodule_path)

if __name__ == "__main__":
    build_submodule()

