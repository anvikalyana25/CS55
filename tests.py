#Anvi Kalyana and Mehar Bhasin
#testing file

import requests
import json
import time

# Configuration
BASE_URL = 'http://localhost:5500'
HEADERS = {'Content-Type': 'application/json'}

def test_whisperchain():
    """Test all WhisperChain+ functionality"""
    
    print("🚀 Starting WhisperChain+ Tests")
    print("=" * 50)
    
    # Health Check
    print("\n1. Testing Health Check...")
    response = requests.get(f'{BASE_URL}/health')
    assert response.status_code == 200
    print("Health check passed")
    
    # Register Users
    print("\n2. Registering Users...")
    
    # Register Admin
    admin_data = {
        'user_id': 'admin1',
        'name': 'System Admin',
        'role': 'admin'
    }
    response = requests.post(f'{BASE_URL}/register', json=admin_data, headers=HEADERS)
    assert response.status_code == 200
    admin_info = response.json()
    print(f"Admin registered: {admin_info['user_id']}")
    
    # Register Sender
    sender_data = {
        'user_id': 'sender1',
        'name': 'Alice Sender',
        'role': 'sender'
    }
    response = requests.post(f'{BASE_URL}/register', json=sender_data, headers=HEADERS)
    assert response.status_code == 200
    sender_info = response.json()
    print(f"Sender registered: {sender_info['user_id']}")
    
    # Register Recipient
    recipient_data = {
        'user_id': 'recipient1',
        'name': 'Bob recipient',
        'role': 'recipient'
    }
    response = requests.post(f'{BASE_URL}/register', json=recipient_data, headers=HEADERS)
    assert response.status_code == 200
    recipient_info = response.json()
    print(f"Recipient registered: {recipient_info['user_id']}")
    
    # Register Moderator
    moderator_data = {
        'user_id': 'moderator1',
        'name': 'Charlie Moderator',
        'role': 'moderator'
    }
    response = requests.post(f'{BASE_URL}/register', json=moderator_data, headers=HEADERS)
    assert response.status_code == 200
    moderator_info = response.json()
    print(f"Moderator registered: {moderator_info['user_id']}")
    
    # Admin Issues Token
    print("\n3. Testing Token Issuance...")
    
    token_request = {
        'sender_id': 'sender1'
    }
    admin_headers = HEADERS.copy()
    admin_headers['Authorization'] = 'admin1'  # Simplified auth
    
    response = requests.post(f'{BASE_URL}/issue-token', json=token_request, headers=admin_headers)
    assert response.status_code == 200
    token_info = response.json()
    sender_token = token_info['token']
    print(f"Token issued: {sender_token[:20]}...")
    
    # Admin Can View Users
    print("\n4. Testing Admin User Management...")
    
    response = requests.get(f'{BASE_URL}/users', headers=admin_headers)
    assert response.status_code == 200
    users_list = response.json()
    print(f"Admin can view {len(users_list['users'])} users")
    
    # Send Anonymous Message
    print("\n5. Testing Anonymous Message Sending...")
    
    message_data = {
        'recipient_id': 'recipient1',
        'message': 'You did an amazing job on that presentation! Keep up the great work!'
    }
    sender_headers = HEADERS.copy()
    sender_headers['Authorization'] = f'Bearer {sender_token}'
    
    response = requests.post(f'{BASE_URL}/send-message', json=message_data, headers=sender_headers)
    assert response.status_code == 200
    message_info = response.json()
    message_id = message_info['message_id']
    print(f"Message sent successfully: {message_id}")
    
    # Recipient Gets Messages
    print("\n6. Testing Message Retrieval...")
    
    recipient_headers = HEADERS.copy()
    recipient_headers['Authorization'] = 'recipient1'
    
    response = requests.get(f'{BASE_URL}/messages', headers=recipient_headers)
    assert response.status_code == 200
    messages_data = response.json()
    print(f"Recipient has {len(messages_data['messages'])} messages")
    
    # Decrypt Message
    print("\n7. Testing Message Decryption...")
    
    decrypt_data = {
        'message_id': message_id
    }
    
    response = requests.post(f'{BASE_URL}/decrypt-message', json=decrypt_data, headers=recipient_headers)
    assert response.status_code == 200
    decrypted_info = response.json()
    decrypted_message = decrypted_info['decrypted_message']
    print(f"Message decrypted: '{decrypted_message[:30]}...'")
    
    # Flag Message
    print("\n8. Testing Message Flagging...")
    
    flag_data = {
        'message_id': message_id
    }
    
    response = requests.post(f'{BASE_URL}/flag-message', json=flag_data, headers=recipient_headers)
    assert response.status_code == 200
    print("Message flagged successfully")
    
    # Moderator Views Queue
    print("\n9. Testing Moderation Queue...")
    
    moderator_headers = HEADERS.copy()
    moderator_headers['Authorization'] = 'moderator1'
    
    response = requests.get(f'{BASE_URL}/moderation-queue', headers=moderator_headers)
    assert response.status_code == 200
    queue_data = response.json()
    print(f"Moderator can see {len(queue_data['flagged_messages'])} flagged messages")
    
    # Freeze Token
    print("\n10. Testing Token Freezing...")
    
    freeze_data = {
        'message_id': message_id
    }
    
    response = requests.post(f'{BASE_URL}/freeze-token', json=freeze_data, headers=moderator_headers)
    assert response.status_code == 200
    print("Token frozen successfully")
    
    # View Audit Log
    print("\n11. Testing Audit Log...")
    
    response = requests.get(f'{BASE_URL}/audit-log', headers=moderator_headers)
    assert response.status_code == 200
    audit_data = response.json()
    print(f"Audit log contains {audit_data['total_entries']} entries")
    
    # Test RBAC - Unauthorized Access
    print("\n12. Testing Role-Based Access Control...")
    
    # Try to access admin endpoint as sender
    sender_headers_simple = HEADERS.copy()
    sender_headers_simple['Authorization'] = 'sender1'
    
    response = requests.get(f'{BASE_URL}/users', headers=sender_headers_simple)
    assert response.status_code == 403
    print("RBAC working: Sender cannot access admin endpoints")
    
    # Try to use token twice
    print("\n13. Testing Token Reuse Prevention...")
    
    message_data2 = {
        'recipient_id': 'recipient1',
        'message': 'This should fail - token already used!'
    }
    
    response = requests.post(f'{BASE_URL}/send-message', json=message_data2, headers=sender_headers)
    assert response.status_code == 400
    print("Token reuse prevented successfully")
    
    # Detailed Audit Log Review
    print("\n14. Reviewing Audit Trail...")
    
    response = requests.get(f'{BASE_URL}/audit-log', headers=admin_headers)
    audit_data = response.json()
    audit_entries = audit_data['audit_log']
    
    print(f"Audit Log Summary ({audit_data['total_entries']} entries):")
    for i, entry in enumerate(audit_entries[-5:], 1):  # Show last 5 entries
        print(f"   {i}. {entry['action_type']} by {entry['role']} at {entry['timestamp']}")
    
    print("\n" + "=" * 50)
    print("🎉 All tests passed! WhisperChain+ is working correctly!")
    print("=" * 50)
    
    # Summary Stats
    print(f"\n Test Summary:")
    print(f"   • Users registered: 4 (Admin, Sender, Recipient, Moderator)")
    print(f"   • Anonymous tokens issued: 1")
    print(f"   • Messages sent: 1")
    print(f"   • Messages flagged: 1")
    print(f"   • Audit log entries: {audit_data['total_entries']}")
    print(f"   • RBAC violations prevented: 2")

def test_error_cases():
    """Test error handling and edge cases"""
    print("\n Testing Error Cases...")
    
    # Test duplicate registration
    duplicate_user = {
        'user_id': 'admin1',  # Already exists
        'name': 'Duplicate Admin',
        'role': 'admin'
    }
    response = requests.post(f'{BASE_URL}/register', json=duplicate_user, headers=HEADERS)
    assert response.status_code == 400
    print("Duplicate registration prevented")
    
    # Test unauthorized token issuance
    token_request = {
        'sender_id': 'sender1'
    }
    unauthorized_headers = HEADERS.copy()
    unauthorized_headers['Authorization'] = 'sender1'  # Sender trying to issue tokens
    
    response = requests.post(f'{BASE_URL}/issue-token', json=token_request, headers=unauthorized_headers)
    assert response.status_code == 403
    print("Unauthorized token issuance prevented")
    
    # Test invalid message recipient
    admin_headers = HEADERS.copy()
    admin_headers['Authorization'] = 'admin1'
    
    # First issue a new token
    token_request = {'sender_id': 'sender1'}
    response = requests.post(f'{BASE_URL}/issue-token', json=token_request, headers=admin_headers)
    new_token = response.json()['token']
    
    message_data = {
        'recipient_id': 'nonexistent_user',
        'message': 'This should fail!'
    }
    sender_headers = HEADERS.copy()
    sender_headers['Authorization'] = f'Bearer {new_token}'
    
    response = requests.post(f'{BASE_URL}/send-message', json=message_data, headers=sender_headers)
    assert response.status_code == 404
    print("Invalid recipient prevented")

if __name__ == '__main__':
    try:
        print("Starting WhisperChain+ Test Suite")
        print("Make sure the Flask server is running on http://localhost:5000")
        time.sleep(1)
        
        # Run main functionality tests
        test_whisperchain()
        
        # Run error case tests
        test_error_cases()
        
        print("\nAll tests completed successfully!")
        
    except AssertionError as e:
        print(f"\n Test failed: {e}")
    except requests.exceptions.ConnectionError:
        print("\n Could not connect to server. Make sure Flask app is running on localhost:5000")
    except Exception as e:
        print(f"\n Unexpected error: {e}")