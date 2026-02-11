from app import create_app

app = create_app()

if __name__ == '__main__':
    print("="*50)
    print("NetRunner OS - Network Simulation Studio")
    print("Starting Flask server...")
    print("Go to http://127.0.0.1:9000")
    print("="*50)
    app.run(host='0.0.0.0', port=9000, debug=True)
