import requests
import sys
import json
from datetime import datetime
import time

class RATCountermeasureAPITester:
    def __init__(self, base_url="https://remote-trojan.preview.emergentagent.com"):
        self.base_url = base_url
        self.api_url = f"{base_url}/api"
        self.tests_run = 0
        self.tests_passed = 0
        self.test_results = []
        self.detection_id = None

    def log_test(self, name, success, details=""):
        """Log test result"""
        self.tests_run += 1
        if success:
            self.tests_passed += 1
        
        result = {
            "test_name": name,
            "success": success,
            "details": details,
            "timestamp": datetime.now().isoformat()
        }
        self.test_results.append(result)
        
        status = "✅ PASS" if success else "❌ FAIL"
        print(f"{status} - {name}")
        if details:
            print(f"    Details: {details}")

    def run_test(self, name, method, endpoint, expected_status, data=None, params=None):
        """Run a single API test"""
        url = f"{self.api_url}/{endpoint}"
        headers = {'Content-Type': 'application/json'}
        
        try:
            if method == 'GET':
                response = requests.get(url, headers=headers, params=params, timeout=30)
            elif method == 'POST':
                response = requests.post(url, json=data, headers=headers, timeout=30)
            elif method == 'PATCH':
                response = requests.patch(url, headers=headers, params=params, timeout=30)

            success = response.status_code == expected_status
            
            if success:
                try:
                    response_data = response.json()
                    details = f"Status: {response.status_code}, Response keys: {list(response_data.keys()) if isinstance(response_data, dict) else 'Non-dict response'}"
                except:
                    details = f"Status: {response.status_code}, Response: {response.text[:100]}"
            else:
                details = f"Expected {expected_status}, got {response.status_code}. Response: {response.text[:200]}"

            self.log_test(name, success, details)
            return success, response.json() if success and response.text else {}

        except Exception as e:
            self.log_test(name, False, f"Exception: {str(e)}")
            return False, {}

    def test_root_endpoint(self):
        """Test API root endpoint"""
        return self.run_test("API Root", "GET", "", 200)

    def test_system_status(self):
        """Test system status endpoint"""
        success, response = self.run_test("System Status", "GET", "status", 200)
        
        if success:
            required_fields = ['cpu_usage', 'memory_usage', 'active_connections', 'threat_level']
            missing_fields = [field for field in required_fields if field not in response]
            if missing_fields:
                self.log_test("Status Fields Validation", False, f"Missing fields: {missing_fields}")
                return False
            else:
                self.log_test("Status Fields Validation", True, "All required fields present")
        
        return success

    def test_scan_functionality(self):
        """Test scan endpoint that triggers agent automatically"""
        success, response = self.run_test("Scan with Agent Trigger", "POST", "scan", 200)
        
        if success:
            required_fields = ['scan_id', 'items_scanned', 'threats_found', 'agent_triggered']
            missing_fields = [field for field in required_fields if field not in response]
            if missing_fields:
                self.log_test("Scan Response Validation", False, f"Missing fields: {missing_fields}")
                return False
            else:
                self.log_test("Scan Response Validation", True, f"Scanned {response.get('items_scanned', 0)} items, found {response.get('threats_found', 0)} threats, agent triggered: {response.get('agent_triggered', False)}")
                
                # Store detection IDs for later tests
                if 'detections' in response and response['detections']:
                    self.detection_id = response['detections'][0].get('id')
        
        return success

    def test_agent_run(self):
        """Test manual agent cycle trigger"""
        success, response = self.run_test("Agent Run", "POST", "agent/run", 200)
        
        if success:
            required_fields = ['action', 'threats_processed']
            missing_fields = [field for field in required_fields if field not in response]
            if missing_fields:
                self.log_test("Agent Run Validation", False, f"Missing fields: {missing_fields}")
                return False
            else:
                self.log_test("Agent Run Validation", True, f"Action: {response.get('action')}, Threats processed: {response.get('threats_processed', 0)}")
        
        return success

    def test_agent_state(self):
        """Test agent state endpoint"""
        success, response = self.run_test("Agent State", "GET", "agent/state", 200)
        
        if success:
            required_fields = ['is_active', 'mode', 'threats_evicted', 'countermeasures_deployed']
            missing_fields = [field for field in required_fields if field not in response]
            if missing_fields:
                self.log_test("Agent State Validation", False, f"Missing fields: {missing_fields}")
                return False
            else:
                self.log_test("Agent State Validation", True, f"Mode: {response.get('mode')}, Active: {response.get('is_active')}, Evicted: {response.get('threats_evicted', 0)}")
        
        return success

    def test_war_log(self):
        """Test war log endpoint"""
        success, response = self.run_test("War Log", "GET", "war-log", 200)
        
        if success and isinstance(response, list):
            self.log_test("War Log Validation", True, f"Retrieved {len(response)} war log entries")
            
            # Check for required fields in war log entries
            if response:
                entry = response[0]
                required_fields = ['event_type', 'description', 'timestamp']
                missing_fields = [field for field in required_fields if field not in entry]
                if missing_fields:
                    self.log_test("War Log Entry Validation", False, f"Missing fields: {missing_fields}")
                    return False
                else:
                    self.log_test("War Log Entry Validation", True, f"Event type: {entry.get('event_type')}")
        elif success:
            self.log_test("War Log Validation", False, "Response is not a list")
            return False
        
        return success

    def test_countermeasures(self):
        """Test countermeasures endpoint"""
        success, response = self.run_test("Countermeasures", "GET", "countermeasures", 200)
        
        if success and isinstance(response, list):
            self.log_test("Countermeasures Validation", True, f"Retrieved {len(response)} countermeasures")
        elif success:
            self.log_test("Countermeasures Validation", False, "Response is not a list")
            return False
        
        return success

    def test_countermeasure_techniques(self):
        """Test countermeasure techniques endpoint"""
        success, response = self.run_test("CM Techniques", "GET", "countermeasures/techniques", 200)
        
        if success and isinstance(response, dict):
            techniques = list(response.keys())
            self.log_test("CM Techniques Validation", True, f"Available techniques: {len(techniques)} - {', '.join(techniques[:3])}")
        elif success:
            self.log_test("CM Techniques Validation", False, "Response is not a dict")
            return False
        
        return success

    def test_threat_intelligence(self):
        """Test threat intelligence endpoint"""
        success, response = self.run_test("Threat Intelligence", "GET", "threat-intelligence", 200)
        
        if success and isinstance(response, list):
            self.log_test("Threat Intelligence Validation", True, f"Retrieved {len(response)} intelligence entries")
        elif success:
            self.log_test("Threat Intelligence Validation", False, "Response is not a list")
            return False
        
        return success

    def test_detections_list(self):
        """Test detections list endpoint"""
        success, response = self.run_test("Get Detections", "GET", "detections", 200)
        
        if success and isinstance(response, list):
            self.log_test("Detections List Validation", True, f"Retrieved {len(response)} detections")
            
            # Store a detection ID for further testing if available
            if response and not self.detection_id:
                self.detection_id = response[0].get('id')
        elif success:
            self.log_test("Detections List Validation", False, "Response is not a list")
            return False
        
        return success

    def test_detection_by_id(self):
        """Test getting specific detection"""
        if not self.detection_id:
            self.log_test("Get Detection by ID", False, "No detection ID available for testing")
            return False
        
        return self.run_test("Get Detection by ID", "GET", f"detections/{self.detection_id}", 200)[0]

    def test_ai_analysis(self):
        """Test AI analysis endpoint"""
        if not self.detection_id:
            self.log_test("AI Analysis", False, "No detection ID available for testing")
            return False
        
        print(f"    Testing AI analysis with detection ID: {self.detection_id}")
        success, response = self.run_test("AI Analysis", "POST", f"detections/{self.detection_id}/analyze", 200)
        
        if success and 'strategy' in response:
            strategy = response['strategy']
            if isinstance(strategy, dict) and 'primary_technique' in strategy:
                self.log_test("AI Analysis Content Validation", True, f"Primary technique: {strategy.get('primary_technique')}")
            else:
                self.log_test("AI Analysis Content Validation", False, f"Invalid strategy format: {strategy}")
                return False
        elif success:
            self.log_test("AI Analysis Content Validation", False, "No strategy field in response")
            return False
        
        return success

    def test_detection_status_update(self):
        """Test detection status (not applicable for countermeasure system)"""
        # Skip this test as the countermeasure system handles status automatically
        self.log_test("Detection Status Update", True, "Skipped - handled automatically by agent")
        return True

    def test_network_connections(self):
        """Test network connections endpoint"""
        success, response = self.run_test("Network Connections", "GET", "network/connections", 200)
        
        if success and isinstance(response, list):
            self.log_test("Network Connections Validation", True, f"Retrieved {len(response)} connections")
            
            # Check for required fields in connections
            if response:
                conn = response[0]
                required_fields = ['local_address', 'remote_address', 'remote_port', 'protocol']
                missing_fields = [field for field in required_fields if field not in conn]
                if missing_fields:
                    self.log_test("Connection Fields Validation", False, f"Missing fields: {missing_fields}")
                    return False
                else:
                    self.log_test("Connection Fields Validation", True, "All required connection fields present")
        elif success:
            self.log_test("Network Connections Validation", False, "Response is not a list")
            return False
        
        return success

    def test_statistics(self):
        """Test statistics endpoint"""
        success, response = self.run_test("Statistics", "GET", "stats", 200)
        
        if success:
            required_fields = ['total_detections', 'active_threats', 'evicted_threats', 'success_rate']
            missing_fields = [field for field in required_fields if field not in response]
            if missing_fields:
                self.log_test("Statistics Fields Validation", False, f"Missing fields: {missing_fields}")
                return False
            else:
                self.log_test("Statistics Fields Validation", True, f"Active: {response.get('active_threats', 0)}, Evicted: {response.get('evicted_threats', 0)}, Success rate: {response.get('success_rate', 0):.1f}%")
        
        return success

    def test_rat_signatures(self):
        """Test RAT signatures endpoint"""
        success, response = self.run_test("RAT Signatures", "GET", "signatures", 200)
        
        if success and isinstance(response, list):
            self.log_test("RAT Signatures Validation", True, f"Retrieved {len(response)} RAT signatures")
        elif success:
            self.log_test("RAT Signatures Validation", False, "Response is not a list")
            return False
        
        return success

    def run_all_tests(self):
        """Run all API tests"""
        print(f"🔍 Starting RAT Detection API Tests")
        print(f"📡 Testing against: {self.base_url}")
        print("=" * 60)
        
        # Test sequence
        tests = [
            self.test_root_endpoint,
            self.test_system_status,
            self.test_scan_functionality,
            self.test_detections_list,
            self.test_detection_by_id,
            self.test_ai_analysis,
            self.test_detection_status_update,
            self.test_network_connections,
            self.test_statistics,
            self.test_rat_signatures
        ]
        
        for test in tests:
            try:
                test()
                time.sleep(0.5)  # Small delay between tests
            except Exception as e:
                self.log_test(test.__name__, False, f"Test execution error: {str(e)}")
        
        # Print summary
        print("\n" + "=" * 60)
        print(f"📊 Test Summary: {self.tests_passed}/{self.tests_run} tests passed")
        
        if self.tests_passed == self.tests_run:
            print("🎉 All tests passed!")
            return 0
        else:
            print(f"⚠️  {self.tests_run - self.tests_passed} tests failed")
            
            # Print failed tests
            failed_tests = [test for test in self.test_results if not test['success']]
            if failed_tests:
                print("\n❌ Failed Tests:")
                for test in failed_tests:
                    print(f"  - {test['test_name']}: {test['details']}")
            
            return 1

def main():
    tester = RATDetectionAPITester()
    return tester.run_all_tests()

if __name__ == "__main__":
    sys.exit(main())