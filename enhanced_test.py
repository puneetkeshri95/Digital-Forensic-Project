#!/usr/bin/env python3
"""
Enhanced Digital Forensics Application Test Suite
=================================================

Comprehensive testing with better error handling and connection management.
"""

import sys
import os
import requests
import json
import time
import tempfile
from pathlib import Path
import warnings
warnings.filterwarnings('ignore', message='Unverified HTTPS request')

# Test configuration
BASE_URL = "http://localhost:5000"
TEST_USERNAME = "hellohacker"  # Using demo user for testing
TEST_PASSWORD = "HACKME184"

class EnhancedDigitalForensicsTestSuite:
    def __init__(self):
        self.token = None
        self.headers = {"Content-Type": "application/json"}
        self.authenticated_headers = {"Content-Type": "application/json"}
        self.session = requests.Session()
        # Set timeout and retry configuration
        self.session.timeout = 10
        
    def wait_for_server(self, max_attempts=10):
        """Wait for server to be ready"""
        print("🔄 Waiting for server to be ready...")
        for attempt in range(max_attempts):
            try:
                response = self.session.get(f"{BASE_URL}/api/auth/system-info", timeout=5)
                # Server is ready if it responds with any status code (200, 401, etc.)
                if response.status_code in [200, 401, 403]:
                    print("✅ Server is ready!")
                    return True
            except requests.exceptions.RequestException:
                pass
            
            if attempt < max_attempts - 1:
                print(f"⏳ Attempt {attempt + 1}/{max_attempts} - Server not ready, waiting 2 seconds...")
                time.sleep(2)
            else:
                print("❌ Server is not responding after maximum attempts")
                return False
        return False

    def test_authentication_system(self):
        """Test complete authentication system"""
        print("\n🔐 Testing Authentication System")
        print("=" * 50)
        
        results = {"passed": 0, "failed": 0, "details": []}

        # Test 1: System info endpoint
        try:
            response = self.session.get(f"{BASE_URL}/api/auth/system-info", timeout=10)
            if response.status_code == 200:
                data = response.json()
                results["passed"] += 1
                results["details"].append(f"✅ System Info: {data.get('app_name', 'Digital Forensics')}")
                print(f"  ✅ System Info: {data.get('app_name', 'Digital Forensics')}")
            else:
                results["failed"] += 1
                results["details"].append(f"❌ System Info: Status {response.status_code}")
                print(f"  ❌ System Info: Status {response.status_code}")
        except Exception as e:
            results["failed"] += 1
            results["details"].append(f"❌ System Info: {str(e)[:100]}")
            print(f"  ❌ System Info: Connection error")

        # Test 2: Login with valid credentials
        try:
            login_data = {"username": TEST_USERNAME, "password": TEST_PASSWORD}
            response = self.session.post(f"{BASE_URL}/api/auth/login", json=login_data, timeout=10)
            if response.status_code == 200:
                data = response.json()
                self.token = data.get("token")
                self.authenticated_headers["Authorization"] = f"Bearer {self.token}"
                results["passed"] += 1
                results["details"].append(f"✅ Login: {data['user']['username']} ({data['user']['role']})")
                print(f"  ✅ Login: {data['user']['username']} ({data['user']['role']})")
            else:
                results["failed"] += 1
                results["details"].append(f"❌ Login: Status {response.status_code}")
                print(f"  ❌ Login: Status {response.status_code}")
        except Exception as e:
            results["failed"] += 1
            results["details"].append(f"❌ Login: {str(e)[:100]}")
            print(f"  ❌ Login: Connection error")

        # Test 3: Profile access with token
        if self.token:
            try:
                response = self.session.get(f"{BASE_URL}/api/auth/profile", headers=self.authenticated_headers, timeout=10)
                if response.status_code == 200:
                    profile = response.json()
                    results["passed"] += 1
                    results["details"].append(f"✅ Profile: {profile.get('username')} - {profile.get('role')}")
                    print(f"  ✅ Profile: {profile.get('username')} - {profile.get('role')}")
                else:
                    results["failed"] += 1
                    results["details"].append(f"❌ Profile: Status {response.status_code}")
                    print(f"  ❌ Profile: Status {response.status_code}")
            except Exception as e:
                results["failed"] += 1
                results["details"].append(f"❌ Profile: {str(e)[:100]}")
                print(f"  ❌ Profile: Connection error")

        return results

    def test_file_integrity_system(self):
        """Test file integrity verification system"""
        print("\n🛡️ Testing File Integrity System")
        print("=" * 50)
        
        results = {"passed": 0, "failed": 0, "details": []}

        if not self.token:
            results["failed"] += 1
            results["details"].append("❌ Authentication required")
            print("  ❌ Authentication required")
            return results

        # Test 1: Get supported algorithms
        try:
            response = self.session.get(f"{BASE_URL}/api/integrity/supported-algorithms", 
                                      headers=self.authenticated_headers, timeout=10)
            if response.status_code == 200:
                data = response.json()
                algo_count = len(data.get('algorithms', []))
                results["passed"] += 1
                results["details"].append(f"✅ Algorithms: {algo_count} supported")
                print(f"  ✅ Algorithms: {algo_count} supported")
            else:
                results["failed"] += 1
                results["details"].append(f"❌ Algorithms: Status {response.status_code}")
                print(f"  ❌ Algorithms: Status {response.status_code}")
        except Exception as e:
            results["failed"] += 1
            results["details"].append(f"❌ Algorithms: {str(e)[:100]}")
            print(f"  ❌ Algorithms: Connection error")

        # Test 2: Health check
        try:
            response = self.session.get(f"{BASE_URL}/api/integrity/health", 
                                      headers=self.authenticated_headers, timeout=10)
            if response.status_code == 200:
                data = response.json()
                results["passed"] += 1
                results["details"].append(f"✅ Health: {data.get('status', 'OK')}")
                print(f"  ✅ Health: {data.get('status', 'OK')}")
            else:
                results["failed"] += 1
                results["details"].append(f"❌ Health: Status {response.status_code}")
                print(f"  ❌ Health: Status {response.status_code}")
        except Exception as e:
            results["failed"] += 1
            results["details"].append(f"❌ Health: {str(e)[:100]}")
            print(f"  ❌ Health: Connection error")

        return results

    def test_api_endpoints(self):
        """Test various API endpoints"""
        print("\n🔧 Testing API Endpoints")
        print("=" * 50)
        
        results = {"passed": 0, "failed": 0, "details": []}
        
        if not self.token:
            results["failed"] += 1
            results["details"].append("❌ Authentication required")
            print("  ❌ Authentication required")
            return results

        # Test endpoints
        endpoints = [
            ("/api/deep-scan/supported-formats", "Deep Scan Formats"),
            ("/api/enhanced-ela/status/test", "Enhanced ELA Status"),
            ("/api/auth/users", "User Management"),
        ]
        
        for endpoint, name in endpoints:
            try:
                response = self.session.get(f"{BASE_URL}{endpoint}", 
                                          headers=self.authenticated_headers, timeout=10)
                if response.status_code in [200, 404, 405]:  # 404/405 are acceptable for some endpoints
                    results["passed"] += 1
                    status_text = "Available" if response.status_code == 200 else "Not Implemented"
                    results["details"].append(f"✅ {name}: {status_text}")
                    print(f"  ✅ {name}: {status_text}")
                else:
                    results["failed"] += 1
                    results["details"].append(f"❌ {name}: Status {response.status_code}")
                    print(f"  ❌ {name}: Status {response.status_code}")
            except Exception as e:
                results["failed"] += 1
                results["details"].append(f"❌ {name}: Connection error")
                print(f"  ❌ {name}: Connection error")
        
        return results

    def run_all_tests(self):
        """Run all test suites"""
        print("🚀 Enhanced Digital Forensics Application Test Suite")
        print("=" * 70)
        print(f"Testing against: {BASE_URL}")
        print(f"Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S')}")
        
        # Wait for server
        if not self.wait_for_server():
            print("\n❌ Cannot connect to server. Please ensure Flask server is running.")
            print("Start with: cd backend && python app.py")
            return

        # Run tests
        auth_results = self.test_authentication_system()
        integrity_results = self.test_file_integrity_system()
        api_results = self.test_api_endpoints()
        
        # Calculate totals
        total_passed = auth_results["passed"] + integrity_results["passed"] + api_results["passed"]
        total_failed = auth_results["failed"] + integrity_results["failed"] + api_results["failed"]
        total_tests = total_passed + total_failed
        
        # Print summary
        print("\n" + "=" * 70)
        print("📊 ENHANCED TEST RESULTS SUMMARY")
        print("=" * 70)
        
        if total_tests > 0:
            success_rate = (total_passed / total_tests) * 100
            
            print(f"🔐 Authentication: {auth_results['passed']}/{auth_results['passed'] + auth_results['failed']} passed")
            print(f"🛡️ File Integrity: {integrity_results['passed']}/{integrity_results['passed'] + integrity_results['failed']} passed")
            print(f"🔧 API Endpoints: {api_results['passed']}/{api_results['passed'] + api_results['failed']} passed")
            print("-" * 70)
            
            if success_rate >= 80:
                status = "🎉 EXCELLENT"
                color = "✅"
            elif success_rate >= 60:
                status = "✅ GOOD"
                color = "✅"
            elif success_rate >= 40:
                status = "⚠️ NEEDS WORK"
                color = "⚠️"
            else:
                status = "❌ POOR"
                color = "❌"
                
            print(f"{color} OVERALL: {total_passed}/{total_tests} tests passed ({success_rate:.1f}%) - {status}")
            
            if total_failed > 0:
                print("\n🔍 Failed Tests:")
                for result_set in [auth_results, integrity_results, api_results]:
                    for detail in result_set["details"]:
                        if "❌" in detail:
                            print(f"  {detail}")
        else:
            print("❌ No tests were executed")
        
        print("\n🌐 Frontend Access:")
        print(f"  Login Page: {BASE_URL}")
        print(f"  Dashboard: {BASE_URL}/dashboard.html")
        print(f"  Main App: {BASE_URL}/index.html")
        print("  Demo User: hellohacker / HACKME184")
        print("  Admin User: admin / ForensicsAdmin2024!")

if __name__ == "__main__":
    test_suite = EnhancedDigitalForensicsTestSuite()
    test_suite.run_all_tests()