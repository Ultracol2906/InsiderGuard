import sqlite3

roles = {
    'Admin': ['EmployeeData', 'PerformanceReports', 'TechnicalLogs', 'HRRecords'],
    'Manager': ['EmployeeData', 'PerformanceReports'],
    'Employee': ['EmployeeData'],
    'Viewer': ['ViewData']  # Example role with limited access
}

# You can assign a default role for the single user
default_role = 'Admin'  # Change this based on the required role

def init_db():
    conn = sqlite3.connect('rbac.db')
    cursor = conn.cursor()

    # Create the users table if it doesn't exist
    cursor.execute('''
        CREATE TABLE users (
            id INTEGER PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL
        )
    ''')

    # Insert test users with different roles
    cursor.execute('''
        INSERT INTO users (username, password, role) 
        VALUES ('admin', 'admin', 'Admin'),
               ('manager', 'manager', 'Manager'),
               ('employee', 'employee', 'Employee'),
               ('viewer', 'viewer', 'Viewer')
    ''')

    conn.commit()
    conn.close()

if __name__ == '__main__':
    init_db()
    print("Database initialized and test users inserted.")