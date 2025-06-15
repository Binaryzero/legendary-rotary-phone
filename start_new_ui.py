#!/usr/bin/env python3
"""
Start script for the new React + FastAPI CVE Research Toolkit
"""

import subprocess
import sys
import time
import os
import signal
from pathlib import Path

def install_backend_deps():
    """Install backend dependencies."""
    print("Installing backend dependencies...")
    try:
        subprocess.run([
            sys.executable, "-m", "pip", "install", 
            "-r", "requirements-backend.txt"
        ], check=True)
        print("Backend dependencies installed successfully")
        return True
    except subprocess.CalledProcessError:
        print("Failed to install backend dependencies")
        return False

def install_frontend_deps():
    """Install frontend dependencies."""
    print("Installing frontend dependencies...")
    frontend_dir = Path("frontend")
    
    if not frontend_dir.exists():
        print("Frontend directory not found")
        return False
    
    try:
        subprocess.run([
            "npm", "install"
        ], cwd=frontend_dir, check=True)
        print("Frontend dependencies installed successfully")
        return True
    except subprocess.CalledProcessError:
        print("Failed to install frontend dependencies")
        return False
    except FileNotFoundError:
        print("npm not found. Please install Node.js")
        return False

def start_backend(port=8000):
    """Start the FastAPI backend."""
    print(f"Starting FastAPI backend on http://localhost:{port}...")
    return subprocess.Popen([
        sys.executable, "-m", "uvicorn", 
        "backend.app:app", 
        "--host", "0.0.0.0", 
        "--port", str(port), 
        "--reload"
    ])

def start_frontend(port=3000):
    """Start the React frontend."""
    print(f"Starting React frontend on http://localhost:{port}...")
    frontend_dir = Path("frontend")
    
    env = os.environ.copy()
    env['PORT'] = str(port)
    
    return subprocess.Popen([
        "npm", "start"
    ], cwd=frontend_dir, env=env)

def main():
    """Main function to start both backend and frontend."""
    print("CVE Research Toolkit - New React + FastAPI Stack")
    print("=" * 60)
    
    # Parse command line arguments
    frontend_port = 3000
    backend_port = 8000
    
    for i, arg in enumerate(sys.argv):
        if arg == "--frontend-port" and i + 1 < len(sys.argv):
            try:
                frontend_port = int(sys.argv[i + 1])
            except ValueError:
                print(f"Invalid frontend port: {sys.argv[i + 1]}")
                sys.exit(1)
        elif arg == "--backend-port" and i + 1 < len(sys.argv):
            try:
                backend_port = int(sys.argv[i + 1])
            except ValueError:
                print(f"Invalid backend port: {sys.argv[i + 1]}")
                sys.exit(1)
    
    # Check if we need to install dependencies
    if "--install" in sys.argv:
        if not install_backend_deps():
            sys.exit(1)
        if not install_frontend_deps():
            sys.exit(1)
        print("\nDependencies installed successfully!")
        print("Run without --install flag to start the application")
        return
    
    backend_proc = None
    frontend_proc = None
    
    try:
        # Start backend
        backend_proc = start_backend(port=backend_port)
        time.sleep(3)  # Give backend time to start
        
        # Check if backend started successfully
        if backend_proc.poll() is not None:
            print("Backend failed to start")
            sys.exit(1)
        
        # Start frontend
        frontend_proc = start_frontend(port=frontend_port)
        time.sleep(5)  # Give frontend time to start
        
        # Check if frontend started successfully
        if frontend_proc.poll() is not None:
            print("Frontend failed to start")
            sys.exit(1)
        
        print("\n" + "=" * 60)
        print(f"✓ Backend running at: http://localhost:{backend_port}")
        print(f"✓ Frontend running at: http://localhost:{frontend_port}")
        print(f"✓ API docs available at: http://localhost:{backend_port}/docs")
        print("\nPress Ctrl+C to stop both services")
        print("=" * 60)
        
        # Keep running until interrupted
        while True:
            time.sleep(1)
            
            # Check if processes are still running
            if backend_proc.poll() is not None:
                print("Backend process died")
                break
            if frontend_proc.poll() is not None:
                print("Frontend process died")
                break
                
    except KeyboardInterrupt:
        print("\nShutting down services...")
    
    finally:
        # Clean up processes
        if backend_proc and backend_proc.poll() is None:
            print("Stopping backend...")
            backend_proc.terminate()
            try:
                backend_proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                backend_proc.kill()
        
        if frontend_proc and frontend_proc.poll() is None:
            print("Stopping frontend...")
            frontend_proc.terminate()
            try:
                frontend_proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                frontend_proc.kill()
        
        print("Services stopped")

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--help":
        print("Usage:")
        print("  python start_new_ui.py --install                     # Install dependencies")
        print("  python start_new_ui.py                               # Start the application")
        print("  python start_new_ui.py --frontend-port 3001          # Use custom frontend port")
        print("  python start_new_ui.py --backend-port 8001           # Use custom backend port")
        print("  python start_new_ui.py --frontend-port 3001 --backend-port 8001  # Use custom ports")
        print("  python start_new_ui.py --help                        # Show this help")
    else:
        main()