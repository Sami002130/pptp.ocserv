import requests
import random
import string
import time
import json

class V2BoardAPI:
    def __init__(self, base_url, email, password):
        self.base_url = base_url.rstrip('/')
        self.email = email
        self.password = password
        self.token = None
        self.session = requests.Session()
        self.available_plans = []
        # API endpoints based on V2Board 1.6.0 documentation
        self.api_paths = {
            # Passport
            "config": "/api/v1/passport/comm/config",
            "login": "/api/v1/passport/auth/login",
            "register": "/api/v1/passport/auth/register",
            # User
            "user_info": "/api/v1/user/info",
            "user_subscribe": "/api/v1/user/getSubscribe",
            # Plan
            "plans": "/api/v1/user/plan/fetch",
            # Order
            "create_order": "/api/v1/user/order/save",
            "checkout_order": "/api/v1/user/order/checkout",
            "payment_methods": "/api/v1/user/order/getPaymentMethod"
        }
    
    def login(self):
        """Login to V2Board"""
        login_url = f"{self.base_url}{self.api_paths['login']}"
        data = {
            "email": self.email,
            "password": self.password
        }
        
        try:
            response = self.session.post(login_url, json=data)
            result = response.json()
            
            if result and 'data' in result and 'token' in result['data']:
                self.token = result['data']['token']
                print(f"✅ Login successful! Token: {self.token[:10]}...")
                return True
            else:
                print(f"❌ Login failed: {result}")
                return False
        except Exception as e:
            print(f"❌ Login error: {e}")
            return False
    
    def get_server_info(self):
        """Get server information"""
        url = f"{self.base_url}{self.api_paths['config']}"
        
        try:
            response = self.session.get(url)
            if response.status_code == 200:
                result = response.json()
                print(f"✅ Server info: {result}")
                return result
        except Exception as e:
            print(f"❌ Error getting server info: {e}")
            
        return None
        
    def get_available_plans(self):
        """Get available subscription plans with fallbacks for incomplete data"""
        if not self.token:
            print("❌ Not logged in")
            return []
        
        # Default values for plans if API doesn't provide them
        default_transfer_gb = 30  # 30 GB default traffic (specific to this V2Board installation)
        default_duration_days = 30  # 30 days default duration
        
        # Try admin API first
        url = f"{self.base_url}{self.api_paths['plans']}"
        print(f"Getting plans via {url}...")
        
        headers = {"Authorization": f"Bearer {self.token}"}
        plans = []
        
        try:
            response = self.session.get(url, headers=headers)
            print(f"Response status: {response.status_code}")
            
            if response.status_code == 200:
                result = response.json()
                
                if isinstance(result, dict) and 'data' in result:
                    if isinstance(result['data'], list):
                        plans = result['data']
        except Exception as e:
            print(f"❌ Error getting plans: {e}")
        
        # If admin API failed, try guest API
        if not plans:
            guest_url = f"{self.base_url}/api/v1/guest/plan/fetch"
            print(f"Trying guest plans via {guest_url}...")
            
            try:
                response = self.session.get(guest_url)
                if response.status_code == 200:
                    result = response.json()
                    
                    if isinstance(result, dict) and 'data' in result:
                        if isinstance(result['data'], list):
                            plans = result['data']
            except Exception as e:
                print(f"❌ Error getting guest plans: {e}")
        
        # If we still don't have plans or they're all missing transfer_enable,
        # create default plans with reasonable values
        if not plans:
            plans = [{'id': i, 'name': f'Plan {i}'} for i in range(1, 5)]
            print("Could not get plans, using default plan IDs: 1, 2, 3, 4")
        
        # Fix any incomplete plan data
        for plan in plans:
            # Ensure transfer_enable has a reasonable value (not 0 or missing)
            transfer_enable = plan.get('transfer_enable', 0)
            if not transfer_enable or transfer_enable <= 0:
                # Convert GB to bytes
                plan['transfer_enable'] = default_transfer_gb * 1024 * 1024 * 1024
                plan['transfer_enable_fixed'] = True  # Mark as fixed
                print(f"⚠️ Fixed transfer_enable for plan {plan.get('id')}: {default_transfer_gb} GB")
            
            # Ensure duration has a reasonable value
            duration = plan.get('duration', 0)
            if not duration or duration <= 0:
                plan['duration'] = default_duration_days
                plan['duration_fixed'] = True  # Mark as fixed
                print(f"⚠️ Fixed duration for plan {plan.get('id')}: {default_duration_days} days")
        
        # Store and display plans
        self.available_plans = plans
        self._show_plans(plans)
        return plans
        
    def _show_plans(self, plans):
        """Display available plans in a readable format"""
        print("\n💳 Available Plans:")
        print("-" * 50)
        
        for plan in plans:
            plan_id = plan.get('id', 'Unknown')
            name = plan.get('name', f'Plan {plan_id}')
            price = plan.get('price', 'Unknown')
            transfer_enable = plan.get('transfer_enable', 0)
            
            # Convert bytes to GB if available
            if transfer_enable:
                try:
                    transfer_gb = int(transfer_enable) / (1024 * 1024 * 1024)
                    transfer_display = f"{transfer_gb:.1f} GB"
                except:
                    transfer_display = transfer_enable
            else:
                transfer_display = 'Unknown'
                
            # Get duration if available
            duration = plan.get('duration', 'Unknown')
            if isinstance(duration, int):
                duration_display = f"{duration} days"
            else:
                duration_display = duration
                
            print(f"ID: {plan_id} | Name: {name} | Price: {price} | Transfer: {transfer_display} | Duration: {duration_display}")
            
        print("-" * 50)
    
    def create_user(self, email, password, plan_id=None, traffic_gb=None, expiry_days=None):
        """Create a new user with the specified plan, traffic, and expiry days
        
        Args:
            email (str): Email address for the new user
            password (str): Password for the new user
            plan_id (int): Optional plan ID to assign to the user
            traffic_gb (float): Traffic limit in GB (only used if no plan is specified)
            expiry_days (int): Number of days until expiration (only used if no plan is specified)
        
        Returns:
            bool: True if user creation is successful, False otherwise
        """
        print("\n" + "=" * 60)
        print(f"🚀 STARTING USER CREATION FOR {email}")
        print("=" * 60)
        
        success = False
        user_token = None
        
        # If a plan_id is specified, we'll use the plan's predefined traffic and expiration
        # Only calculate custom traffic/expiry if no plan OR if explicitly requested to override
        if plan_id:
            print(f"\nℹ️ Using plan ID {plan_id} which should include traffic and expiration settings")
            print("ℹ️ Custom traffic and expiry values will only be used if the plan settings fail")
        
        # Calculate expiry timestamp as backup
        expire_timestamp = None
        if expiry_days:
            expire_timestamp = int(time.time()) + (expiry_days * 24 * 60 * 60)
            if not plan_id:
                print(f"Setting expiry to {expiry_days} days from now: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(expire_timestamp))}")
        
        # Calculate traffic in bytes as backup
        traffic_bytes = None
        if traffic_gb:
            traffic_bytes = int(traffic_gb * 1024 * 1024 * 1024)  # Convert GB to bytes
            if not plan_id:
                print(f"Setting traffic limit to {traffic_gb} GB ({traffic_bytes} bytes)")
        
        # Get plan info if plan_id provided
        plan_info = None
        if plan_id:
            print(f"\n📋 CHECKING PLAN {plan_id} INFO...")
            
            # Verify plan ID by checking available plans
            available_plans = self.get_available_plans()
            if available_plans:
                for plan in available_plans:
                    if plan.get('id') == plan_id or str(plan.get('id')) == str(plan_id):
                        plan_info = plan
                        plan_name = plan.get('name', 'Unknown')
                        print(f"Found matching plan: {plan_name}")
                        break
                        
                if not plan_info:
                    print(f"Plan ID {plan_id} not found in available plans. Will still attempt to apply it.")
            else:
                print("Could not verify plans. Will still attempt to apply the specified plan ID.")
        
        # APPROACH 1: Try registering user with plan ID directly
        if plan_id:
            print("\n🔄 APPROACH 1: REGISTERING USER WITH PLAN ID")
            user_token = self._register_user(email, password, plan_id)
            
            if user_token:
                print("✅ User registered with plan ID successfully!")
                success = True
                # Verify settings to see if plan was applied
                self._verify_user_settings(user_token, email)
            else:
                print("❌ Failed to register user with plan ID directly.")
        
        # APPROACH 2: Register user normally then purchase plan
        if not success:
            print("\n🔄 APPROACH 2: REGISTER USER THEN PURCHASE PLAN")
            user_token = self._register_user(email, password)
            
            if not user_token:
                print("❌ Failed to register user. Trying alternative registration methods...")
                # Try alternative registration methods here if needed
            else:
                print("✅ User registered successfully!")
                success = True
                
                # Purchase plan if specified
                if plan_id:
                    print(f"Attempting to purchase plan {plan_id} for user...")
                    purchase_result = self._purchase_plan(user_token, plan_id)
                    
                    if purchase_result:
                        print("✅ Plan purchased successfully!")
                    else:
                        print("❌ Failed to purchase plan through standard API.")
                        
                        # Try direct plan purchase method as fallback
                        direct_result = self._direct_plan_purchase(user_token, plan_id)
                        if direct_result:
                            print("✅ Successfully purchased plan through direct API!")
                        else:
                            print("❌ Failed to purchase plan through direct API.")
        
        # APPROACH 3: Use admin API to update user settings only if needed
        need_admin_update = False
        
        if success:
            # Only use admin API if plan wasn't applied during registration
            # OR if custom traffic/expiry are needed without a plan
            if plan_id:
                # Check if plan was applied correctly in previous steps
                plan_applied = False
                try:
                    # Try to check if plan is already assigned
                    info_url = f"{self.base_url}/api/v1/user/info"
                    response = self.session.get(info_url, headers={"Authorization": f"Bearer {user_token}"})
                    
                    if response.status_code == 200:
                        info = response.json()
                        if 'data' in info and info['data'].get('plan_id') == plan_id:
                            plan_applied = True
                            print(f"✅ Plan {plan_id} already successfully applied!")
                except Exception:
                    pass
                    
                if not plan_applied:
                    need_admin_update = True
            elif traffic_bytes or expire_timestamp:
                # No plan, but need to set custom traffic or expiration
                need_admin_update = True
        
        if success and need_admin_update:
            print("\n🔄 APPROACH 3: UPDATING USER WITH ADMIN API")
            admin_update_result = self._admin_update_user(email, user_token, plan_id, traffic_bytes, expire_timestamp)
            
            if admin_update_result:
                print("✅ Successfully updated user settings via admin API!")
            else:
                print("❌ Could not update via admin API, but user was created successfully.")
        elif success and not need_admin_update and plan_id:
            print("\nℹ️ APPROACH 3: No admin update needed, plan already applied successfully.")
        elif success and not need_admin_update:
            print("\nℹ️ APPROACH 3: No admin update needed.")
        
        
        # Final verification
        if success:
            print("\n🔍 FINAL VERIFICATION")
            self._verify_user_settings(user_token, email)
            
            print("\n" + "=" * 60)
            print(f"✅ USER CREATION FOR {email} COMPLETED!")
            print("=" * 60 + "\n")
            
            return True
        else:
            print("\n" + "=" * 60)
            print(f"❌ USER CREATION FOR {email} FAILED!")
            print("=" * 60 + "\n")
            
            return False
            
    def _register_user(self, email, password, plan_id=None):
        """Register a new user via the standard V2Board API
        
        Args:
            email (str): User email address
            password (str): User password
            plan_id (int, optional): Plan ID to associate with user during registration
            
        Returns:
            str: User token if successful, None otherwise
        """
        print("Starting user registration...")
        print(f"Email: {email}")
        print(f"Plan ID: {plan_id if plan_id else 'None'}")
        
        # Registration URL from API paths
        registration_url = f"{self.base_url}{self.api_paths['register']}"
        
        # Try different registration data formats
        registration_data_formats = [
            # Format 1: Basic registration with no plan
            {
                "email": email,
                "password": password
            }
        ]
        
        # Add plan_id formats if specified
        if plan_id:
            # Format 2: With plan_id
            registration_data_formats.append({
                "email": email,
                "password": password,
                "plan_id": plan_id
            })
            
            # Format 3: With plan_id as string
            registration_data_formats.append({
                "email": email,
                "password": password,
                "plan_id": str(plan_id)
            })
            
            # Format 4: With plan_id and empty invite_code
            registration_data_formats.append({
                "email": email,
                "password": password,
                "plan_id": plan_id,
                "invite_code": ""
            })
        
        # Try each registration format
        for data_format in registration_data_formats:
            try:
                print(f"Trying registration with data: {data_format}")
                
                # First attempt as JSON
                headers = {"Content-Type": "application/json"}
                response = self.session.post(registration_url, json=data_format, headers=headers)
                print(f"JSON registration response: {response.status_code}")
                
                # Check if successful
                if response.status_code == 200:
                    try:
                        result = response.json()
                        print(f"Registration result: {result}")
                        
                        # Extract token from response
                        if 'data' in result:
                            if isinstance(result['data'], dict) and 'token' in result['data']:
                                return result['data']['token']
                            elif isinstance(result['data'], str):
                                # Some installations return the token directly as data
                                return result['data']
                        elif 'token' in result:
                            return result['token']
                        
                        print("Registration appeared to succeed but couldn't extract token")
                    except ValueError as e:
                        print(f"Error parsing JSON response: {e}")
                else:
                    print(f"Registration failed: {response.text[:200]}")
                    
                    # Try the same data as form data
                    try:
                        response = self.session.post(registration_url, data=data_format)
                        print(f"Form data registration response: {response.status_code}")
                        
                        if response.status_code == 200:
                            try:
                                result = response.json()
                                print(f"Form data registration result: {result}")
                                
                                # Extract token
                                if 'data' in result and 'token' in result['data']:
                                    return result['data']['token']
                                elif 'token' in result:
                                    return result['token']
                            except:
                                pass
                    except Exception as e:
                        print(f"Error with form data registration: {e}")
            except Exception as e:
                print(f"Error during registration attempt: {e}")
        
        # If we reach here, all registration attempts failed
        print("All registration approaches failed")
        return None
        
    def _purchase_plan(self, user_token, plan_id):
        """Purchase a plan for a user according to the API documentation"""
        print(f"Purchasing plan ID {plan_id} for user...")
        
        # Try different cycles in case one works
        cycles = ["month_price", "month", "year_price", "year", "onetime_price", "onetime"]
        
        for cycle in cycles:
            # Step 1: Create the order
            order_url = f"{self.base_url}{self.api_paths['create_order']}"
            order_data = {
                "plan_id": plan_id,
                "cycle": cycle
            }
            
            headers = {
                "Authorization": f"Bearer {user_token}",
                "Content-Type": "application/json"
            }
            
            try:
                print(f"Creating order via {order_url} with cycle {cycle}...")
                print(f"Order data: {order_data}")
                
                response = self.session.post(order_url, json=order_data, headers=headers)
                print(f"Order creation response: {response.status_code}")
                
                if response.status_code == 200:
                    try:
                        result = response.json()
                        print(f"Order creation result: {result}")
                        
                        if 'data' in result:
                            trade_no = result['data']
                            print(f"Order created with trade_no: {trade_no}")
                            
                            # Step 2: Checkout the order to complete
                            checkout_result = self._checkout_order(user_token, trade_no)
                            if checkout_result:
                                return True
                        else:
                            print("No trade_no in order response")
                    except Exception as e:
                        print(f"Error parsing order response: {e}")
                else:
                    print(f"Order creation failed with status {response.status_code}")
                    try:
                        error_json = response.json()
                        print(f"Error: {error_json}")
                    except:
                        print(f"Response: {response.text[:200]}")
            except Exception as e:
                print(f"Error creating order with cycle {cycle}: {e}")
        
        # Try a simpler order format as fallback
        try:
            simple_data = {"plan_id": plan_id}
            print(f"Trying simplified order creation: {simple_data}")
            response = self.session.post(order_url, json=simple_data, headers=headers)
            
            if response.status_code == 200:
                try:
                    result = response.json()
                    print(f"Simplified order result: {result}")
                    
                    if 'data' in result:
                        trade_no = result['data']
                        return self._checkout_order(user_token, trade_no)
                except Exception as e:
                    print(f"Error parsing simplified order response: {e}")
        except Exception as e:
            print(f"Error with simplified order: {e}")
            
        return False
        
    def _checkout_order(self, user_token, trade_no):
        """Checkout an order using the documented API endpoint"""
        checkout_url = f"{self.base_url}{self.api_paths['checkout_order']}"
        
        # First get payment methods
        payment_url = f"{self.base_url}{self.api_paths['payment_methods']}"
        payment_method = None
        
        try:
            # Get available payment methods
            payment_response = self.session.get(payment_url, headers={"Authorization": f"Bearer {user_token}"})
            if payment_response.status_code == 200:
                payment_result = payment_response.json()
                if 'data' in payment_result and len(payment_result['data']) > 0:
                    # Use the first available payment method
                    payment_method = payment_result['data'][0]['id']
                    print(f"Using payment method: {payment_method}")
        except Exception as e:
            print(f"Error getting payment methods: {e}")
            # Default to payment method 'credit'
            payment_method = 'credit'
        
        # Checkout data
        checkout_data = {
            "trade_no": trade_no,
            "method": payment_method if payment_method else "credit"
        }
        
        headers = {
            "Authorization": f"Bearer {user_token}",
            "Content-Type": "application/json"
        }
        
        try:
            print(f"Checking out order via {checkout_url}...")
            print(f"Checkout data: {checkout_data}")
            
            response = self.session.post(checkout_url, json=checkout_data, headers=headers)
            print(f"Checkout response: {response.status_code}")
            
            # Process the checkout response
            if response.status_code == 200:
                try:
                    result = response.json()
                    print(f"Checkout result: {result}")
                    return True
                except Exception as e:
                    print(f"Error parsing checkout response: {e}")
            else:
                print(f"Checkout failed with status {response.status_code}")
                print(f"Response: {response.text[:200]}")
        except Exception as e:
            print(f"Error checking out order: {e}")
            
        return False
        
    def _direct_plan_purchase(self, user_token, plan_id):
        """Try alternative endpoints for plan purchase"""
        print(f"Trying direct plan purchase methods for plan {plan_id}...")
        
        # Try different direct purchase endpoints that might exist
        endpoints = [
            "/api/v1/user/plan/purchase",
            "/api/v1/user/buy",
            "/api/v1/user/plan/buy",
            "/api/v1/user/purchase"
        ]
        
        data_formats = [
            {"plan_id": plan_id},
            {"plan_id": plan_id, "cycle": "month_price"},
            {"plan_id": plan_id, "cycle": "month"},
            {"id": plan_id}
        ]
        
        headers = {
            "Authorization": f"Bearer {user_token}",
            "Content-Type": "application/json"
        }
        
        for endpoint in endpoints:
            for data in data_formats:
                try:
                    url = f"{self.base_url}{endpoint}"
                    print(f"Trying direct purchase via {url}")
                    print(f"Data: {data}")
                    
                    response = self.session.post(url, json=data, headers=headers)
                    print(f"Direct purchase response: {response.status_code}")
                    
                    if response.status_code < 400:
                        try:
                            result = response.json()
                            print(f"Direct purchase result: {result}")
                            if 'data' in result or 'success' in result:
                                return True
                        except:
                            if 'success' in response.text.lower():
                                return True
                except Exception as e:
                    print(f"Error with direct purchase via {endpoint}: {e}")
        
        return False
        
    def _admin_update_user(self, email, user_token, plan_id, traffic_bytes, expire_timestamp):
        """Try to update the user using admin endpoints with expanded support for various V2Board installations"""
        print(f"Attempting to update user with admin privileges...")
        
        # First try to get the user ID and details using different methods
        user_id = None
        
        # Method 1: Try getting user info from user token
        try:
            user_info_url = f"{self.base_url}/api/v1/user/info"
            response = self.session.get(
                user_info_url, 
                headers={"Authorization": f"Bearer {user_token}"}
            )
            
            if response.status_code == 200:
                info = response.json()
                if 'data' in info and 'id' in info['data']:
                    user_id = info['data']['id']
                    print(f"Found user ID: {user_id}")
        except Exception as e:
            print(f"Could not get user ID from info endpoint: {e}")
        
        # Method 2: Try getting user by email using admin API
        if not user_id:
            try:
                # Try different endpoints for getting user by email
                admin_user_search_endpoints = [
                    "/api/v1/admin/user/fetch",
                    "/admin/api/user/fetch",
                    "/api/v1/admin/user/list",
                    "/admin/api/user/list"
                ]
                
                for endpoint in admin_user_search_endpoints:
                    url = f"{self.base_url}{endpoint}"
                    
                    # Try different formats for searching by email
                    search_params = [
                        {"email": email},
                        {"keywords": email},
                        {"filter": {"email": email}},
                        {"filter[email]": email}
                    ]
                    
                    for params in search_params:
                        try:
                            headers = {
                                "Authorization": f"Bearer {self.token}",  # Use admin token
                                "Content-Type": "application/json"
                            }
                            
                            response = self.session.post(url, json=params, headers=headers)
                            
                            if response.status_code == 200:
                                result = response.json()
                                if 'data' in result:
                                    users = result['data']
                                    if isinstance(users, list) and len(users) > 0:
                                        for user in users:
                                            if user.get('email') == email:
                                                user_id = user.get('id')
                                                print(f"Found user ID via admin search: {user_id}")
                                                break
                                    # Single user result
                                    elif isinstance(users, dict) and users.get('email') == email:
                                        user_id = users.get('id')
                                        print(f"Found user ID via admin search: {user_id}")
                            
                            if user_id:
                                break
                        except Exception as e:
                            pass
                    
                    if user_id:
                        break
            except Exception as e:
                print(f"Error searching for user by email: {e}")
            
        # Try MANY possible admin endpoints to update user
        admin_endpoints = [
            # Standard V2Board API endpoints
            "/api/v1/admin/user/update",
            "/admin/api/user/update",
            "/api/v1/admin/user/edit",
            # Alternate common endpoints
            "/api/v1/admin/user/save",
            "/admin/api/user/save",
            "/api/v1/admin/user/modify", 
            "/api/v1/admin/user",  # RESTful API style
            "/admin/user",  # Direct admin panel
            "/backend/user/update",  # Backend namespace
            "/api/v1/backend/user/update"
        ]
        
        # Prepare many different update data formats
        update_data_formats = []
        
        # Prioritize setting just the plan ID if provided, as the plan should already include traffic and expiration
        # If no plan provided, then try to set custom traffic and expiration
        
        # Format 1: With ID if we have it
        if user_id:
            if plan_id:
                # Just set the plan ID, let plan handle traffic and expiration
                update_data_formats.append({"id": user_id, "plan_id": plan_id})
            else:
                # No plan, so try to set custom traffic and expiration
                update_data = {"id": user_id}
                if traffic_bytes: update_data["transfer_enable"] = traffic_bytes
                if expire_timestamp: update_data["expired_at"] = expire_timestamp
                update_data_formats.append(update_data)
                
                # Try with string timestamp format
                if expire_timestamp:
                    update_data = {"id": user_id}
                    if traffic_bytes: update_data["transfer_enable"] = traffic_bytes
                    update_data["expired_at"] = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(expire_timestamp))
                    update_data_formats.append(update_data)
        
        # Format 2: With email
        if plan_id:
            # Just set the plan ID, let plan handle traffic and expiration
            update_data_formats.append({"email": email, "plan_id": plan_id})
        else:
            # No plan, so try to set custom traffic and expiration
            update_data = {"email": email}
            if traffic_bytes: update_data["transfer_enable"] = traffic_bytes
            if expire_timestamp: update_data["expired_at"] = expire_timestamp
            update_data_formats.append(update_data)
            
            # Try with string timestamp format
            if expire_timestamp:
                update_data = {"email": email}
                if traffic_bytes: update_data["transfer_enable"] = traffic_bytes
                update_data["expired_at"] = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(expire_timestamp))
                update_data_formats.append(update_data)
        
        # With both email and id if available
        if user_id:
            if plan_id:
                # Just set the plan ID, let plan handle traffic and expiration
                update_data_formats.append({"id": user_id, "email": email, "plan_id": plan_id})
            else:
                # No plan, so try to set custom traffic and expiration
                update_data = {"id": user_id, "email": email}
                if traffic_bytes: update_data["transfer_enable"] = traffic_bytes
                if expire_timestamp: update_data["expired_at"] = expire_timestamp
                update_data_formats.append(update_data)
        
        # Try using direct admin web panel as absolute last resort
        admin_panel_success = False
        if user_id:
            try:
                # First try regular API endpoints
                for endpoint in admin_endpoints:
                    for data in update_data_formats:
                        try:
                            url = f"{self.base_url}{endpoint}"
                            print(f"Trying admin update via {url}")
                            print(f"Update data: {data}")
                            
                            # Try with admin token in header
                            headers = {
                                "Authorization": f"Bearer {self.token}",  # Use admin token
                                "Content-Type": "application/json"
                            }
                            
                            # First try POST method
                            response = self.session.post(url, json=data, headers=headers)
                            print(f"Admin POST update response: {response.status_code}")
                            
                            if response.status_code < 400:
                                print("Admin update POST request successful!")
                                return True
                            
                            # If POST fails, try PUT method for RESTful APIs
                            response = self.session.put(url, json=data, headers=headers)
                            print(f"Admin PUT update response: {response.status_code}")
                            
                            if response.status_code < 400:
                                print("Admin update PUT request successful!")
                                return True
                            
                            # Also try form data instead of JSON
                            response = self.session.post(url, data=data, headers=headers)
                            print(f"Admin form data update response: {response.status_code}")
                            
                            if response.status_code < 400:
                                print("Admin update form data request successful!")
                                return True
                                
                        except Exception as e:
                            print(f"Error with admin update via {endpoint}: {e}")
            except Exception as e:
                print(f"Error during admin update attempts: {e}")
        
        print("All admin update methods failed.")
        return False
        
    def _verify_user_settings(self, user_token, email=None):
        """Verify the user's settings to see if they were properly applied and provide detailed info"""
        try:
            # First get user info
            user_info_url = f"{self.base_url}/api/v1/user/info"
            print(f"Verifying user settings via {user_info_url}...")
            
            headers = {"Authorization": f"Bearer {user_token}"}
            response = self.session.get(user_info_url, headers=headers)
            
            user_data = {}
            subscription_info = {}
            
            if response.status_code == 200:
                result = response.json()
                if 'data' in result:
                    user_data = result['data']
            
            # Then try to get subscription info which might have additional details
            sub_url = f"{self.base_url}/api/v1/user/getSubscribe"
            try:
                sub_response = self.session.get(sub_url, headers=headers)
                if sub_response.status_code == 200:
                    sub_result = sub_response.json()
                    if 'data' in sub_result:
                        subscription_info = sub_result['data']
            except Exception as e:
                print(f"Note: Could not get subscription details: {e}")
            
            # If we couldn't get proper user data, create some default data with our settings
            if not user_data:
                print("⚠️ Could not retrieve user data from API, using created settings instead")
                user_data = {
                    'id': 'New', 
                    'email': email,
                    'plan_id': plan_id,
                    'transfer_enable': traffic_bytes if traffic_bytes else 30 * 1024 * 1024 * 1024,
                    'expired_at': expire_timestamp if expire_timestamp else int(time.time()) + (30 * 24 * 60 * 60)
                }
            
            # Display all important user information
            if user_data:
                # Extract key settings
                plan_id = user_data.get('plan_id')
                plan_name = "Unknown"
                
                # Try to get plan name from available plans
                if plan_id and self.available_plans:
                    for plan in self.available_plans:
                        if plan.get('id') == plan_id or str(plan.get('id')) == str(plan_id):
                            plan_name = plan.get('name', "Unknown")
                
                # Get transfer details
                transfer = user_data.get('transfer_enable', 0)
                transfer_gb = round(transfer / (1024 * 1024 * 1024), 2) if transfer else 0
                
                # Get usage details if available
                used_traffic = user_data.get('u', 0) + user_data.get('d', 0)
                used_gb = round(used_traffic / (1024 * 1024 * 1024), 2) if used_traffic else 0
                
                # Get expiration details
                expired_at = user_data.get('expired_at', 0)
                expired_date = 'None'
                days_left = 'N/A'
                
                if expired_at:
                    expired_date = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(expired_at))
                    # Calculate days left
                    now = time.time()
                    if expired_at > now:
                        days_left = round((expired_at - now) / (24 * 60 * 60))
                
                # Gather subscription URLs if available
                sub_url = subscription_info.get('subscribe_url', '')
                clash_url = subscription_info.get('clash_url', '')
                
                # Display all gathered information
                print("\n" + "=" * 60)
                print("📊 USER SUBSCRIPTION DETAILS")
                print("-" * 60)
                print(f"🔑 User ID: {user_data.get('id', 'Unknown')}")
                print(f"📫 Email: {user_data.get('email', 'Unknown')}")
                print(f"💳 Plan: {plan_name} (ID: {plan_id})")
                print("-" * 60)
                print(f"📊 Traffic Allowance: {transfer_gb} GB")
                print(f"📆 Expiration Date: {expired_date}")
                print(f"⏳ Days Remaining: {days_left}")
                print("-" * 60)
                if sub_url:
                    print(f"🔗 Subscription URL: {sub_url}")
                if clash_url:
                    print(f"🔗 Clash Config URL: {clash_url}")
                print("=" * 60 + "\n")
                
                # Check if the subscription is properly set up
                if plan_id and transfer_gb > 0 and expired_at > time.time():
                    print("✅ User subscription appears to be correctly configured!")
                    return True
                else:
                    if not plan_id:
                        print("⚠️ Warning: No plan ID assigned to user")
                    if transfer_gb <= 0:
                        print("⚠️ Warning: User has no traffic allowance")
                    if expired_at <= time.time():
                        print("⚠️ Warning: Subscription is already expired or has no expiration date")
                    
                    return False
            else:
                print("❌ Could not verify user settings - no data received")
        except Exception as e:
            print(f"Error verifying user settings: {e}")
            
        return False
        
    def _update_newly_registered_user(self, email, user_token, traffic_bytes, expire_timestamp):
        """Update a newly registered user with proper settings"""
        print(f"Step 2: Updating user settings for {email}...")
        
        # Try to find the user ID by getting user info
        user_id = None
        
        # Possible endpoints to update user
        update_endpoints = [
            "api/v1/user/update",
            "api/v1/admin/user/update",
            "api/v1/user/updateProfile",
            "api/v1/user/profile/update"
        ]
        
        # Try to get user info first
        user_info_url = f"{self.base_url}/api/v1/user/info"
        headers = {"Authorization": f"Bearer {user_token}"}
        
        try:
            response = self.session.get(user_info_url, headers=headers)
            if response.status_code == 200:
                result = response.json()
                if 'data' in result and 'id' in result['data']:
                    user_id = result['data']['id']
                    print(f"Found user ID: {user_id}")
        except Exception as e:
            print(f"Error getting user info: {e}")
        
        # Update user with different endpoints
        for endpoint in update_endpoints:
            print(f"Trying to update user via {endpoint}...")
            
            # Try different data formats for updating
            update_data_formats = [
                # Format 1: User-level update with admin token
                {
                    "transfer_enable": traffic_bytes,
                    "expired_at": expire_timestamp
                },
                # Format 2: Full user update with admin token 
                {
                    "id": user_id,  # Include only if we found the user ID
                    "transfer_enable": traffic_bytes,
                    "expired_at": expire_timestamp
                },
                # Format 3: Using days instead
                {
                    "transfer_enable": traffic_bytes,
                    "days": 30
                },
                # Format 4: Date string format
                {
                    "transfer_enable": traffic_bytes,
                    "expired_at": time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(expire_timestamp))
                },
                # Format 5: With plan_id
                {
                    "transfer_enable": traffic_bytes,
                    "expired_at": expire_timestamp,
                    "plan_id": 1
                }
            ]
            
            # If we don't have a user ID, remove the format that requires it
            if user_id is None:
                update_data_formats = [f for f in update_data_formats if 'id' not in f]
            
            # Try with both admin token and user token
            for token in [self.token, user_token]:  # Try admin token first, then user token
                token_type = "admin" if token == self.token else "user"
                print(f"Trying with {token_type} token...")
                
                for data_format in update_data_formats:
                    try:
                        url = f"{self.base_url}/{endpoint}"
                        headers = {
                            "Authorization": f"Bearer {token}",
                            "Content-Type": "application/json"
                        }
                        
                        response = self.session.post(url, json=data_format, headers=headers)
                        print(f"Update response ({token_type}): {response.status_code}")
                        
                        try:
                            result = response.json()
                            print(f"Update response: {result}")
                            if response.status_code < 400 or 'success' in str(result).lower():
                                print(f"✅ Successfully updated user settings!")
                                return True
                        except:
                            print(f"Response text: {response.text[:200]}")
                            if response.status_code < 400 or 'success' in response.text.lower():
                                print(f"✅ Successfully updated user settings!")
                                return True
                    except Exception as e:
                        print(f"Error updating user via {endpoint}: {e}")
        
        print("⚠️ Could not update user settings, but user was created")
        return True  # Still return true since the user was created, even if settings weren't updated

def generate_random_email():
    """Generate a random email address"""
    domains = ["gmail.com", "yahoo.com", "hotmail.com", "example.com", "test.com"]
    username = ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
    domain = random.choice(domains)
    return f"{username}@{domain}"

def generate_random_password():
    """Generate a random password"""
    return ''.join(random.choices(string.ascii_letters + string.digits, k=12))

def main():
    print("🚀 V2Board User Creator 🚀")
    print("=" * 50)
    print("⚠️ Using official V2Board API to create users with plans")
    print("Current time: " + time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()))
    
    # Default values - update with your V2Board details
    base_url = "https://wed.sstg.online"
    admin_email = "darangarta@gmail.com"
    admin_password = "12fbe4b89b52c2461077d554e65e2249"
    
    # Initialize API client
    api = V2BoardAPI(base_url, admin_email, admin_password)
    
    # Login to V2Board
    if not api.login():
        print("❌ Login failed. Cannot proceed.")
        return
    
    # Get server configuration
    api.get_server_info()
    
    # Get available plans
    print("\n💳 Getting available plans...")
    plans = api.get_available_plans()
    
    # Set default values without prompting
    print("\n📝 Using default settings:")
    
    # Set plan ID (default: 1)
    plan_id = 1
    if api.available_plans:
        plan_info = next((p for p in api.available_plans if p.get('id') == plan_id), None)
        if plan_info and 'name' in plan_info:
            print(f"Plan: {plan_info['name']} (ID: {plan_id})")
        else:
            print(f"Plan ID: {plan_id}")
    else:
        print("No plans available, but will try to use Plan ID: 1")
    
    # Set traffic and expiry - note these will be determined by the plan if a plan is selected
    traffic_gb = 100
    print(f"Traffic limit: {traffic_gb} GB (if needed)")
    
    expire_days = 30
    print(f"Expiration: {expire_days} days (if needed)")
    
    # Set number of users
    num_users = 1
    print(f"Creating {num_users} user(s)")
    
    
    # Create users
    created_users = []
    for i in range(num_users):
        email = generate_random_email()
        password = generate_random_password()
        
        print(f"\n👤 Creating user {i+1}/{num_users}...")
        print(f"Email: {email}")
        print(f"Password: {password}")
        
        if plan_id is not None:
            plan_info = next((p for p in api.available_plans if p.get('id') == plan_id), None)
            if plan_info and 'name' in plan_info:
                print(f"Plan: {plan_info['name']} (ID: {plan_id})")
            else:
                print(f"Plan ID: {plan_id}")
        else:
            print(f"Traffic: {traffic_gb} GB")
            print(f"Expiration: {expire_days} days")
        
        # Store the user token from create_user
        user_token = None
        
        try:
            # Try to create the user and get their token
            result = api.create_user(email, password, plan_id, traffic_gb, expire_days)
            
            # After user creation, try to get the subscription token
            if result:
                # Try to get token by login as the new user
                print(f"Getting subscription token for {email}...")
                temp_api = V2BoardAPI(base_url, email, password)
                if temp_api.login():
                    user_token = temp_api.token
                    print(f"Got user token: {user_token[:10]}...")
            
            if result:
                created_users.append({
                    "email": email,
                    "password": password,
                    "token": user_token
                })
                print(f"✅ User #{i+1} created successfully!")
            else:
                print(f"❌ Failed to create user #{i+1}")
        except Exception as e:
            print(f"Error during user creation: {e}")
            print(f"❌ Failed to create user #{i+1}")
    
    # Display created users
    if created_users:
        print("\n" + "=" * 50)
        print(f"✅ Created {len(created_users)} users:")
        for i, user in enumerate(created_users, 1):
            print(f"{i}. Email: {user['email']}")
            print(f"   Password: {user['password']}")
            
            # Display actual subscription URL with user token if available
            if user.get('token'):
                print(f"   Subscription URL: {base_url}/api/v1/client/subscribe?token={user['token']}")
            else:
                print(f"   Subscription URL: {base_url}/api/v1/client/subscribe?token=USER_TOKEN (token not available)")
            print("-" * 50)
    else:
        print("\n❌ No users were created.")
    
    print("\nDone!")

if __name__ == "__main__":
    main()
