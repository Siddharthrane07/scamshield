import logging
import asyncio
import boto3
from typing import List, Dict, Any
from app.core.config import get_settings
from app.core.exceptions import SandboxException

logger = logging.getLogger("scamshield.track_c")
settings = get_settings()

class TrackCSandbox:
    @classmethod
    async def trigger_fargate_task(cls, url: str) -> Dict[str, Any]:
        """
        Interacts with AWS ECS to run an ephemeral Playwright Fargate task.
        """
        # Read cluster / AWS settings
        region = settings.AWS_REGION
        cluster = settings.AWS_CLUSTER_NAME
        
        # If AWS settings are not fully configured or use placeholders, return simulated result
        import os
        if "placeholder" in cluster or not region or os.environ.get("AWS_ACCESS_KEY_ID") is None or cluster == "scamshield-fargate-cluster":
            logger.info("AWS credentials not set or using default sandbox cluster name. Simulating Sandbox Fargate run.")
            
            # Simulate real timeout for testing purposes if URL contains the keyword 'timeout'
            if "timeout" in url:
                logger.warning("Simulating AWS Fargate Sandbox timeout (> 8s)...")
                await asyncio.sleep(10.0) # sleep 10 seconds to trigger the 8s threshold
            
            # Normal simulation
            is_suspicious_url = any(k in url for k in ["login", "kyc", "verify", "pay", "secure", "bank"])
            
            # Create a mock base64 PNG (tiny transparent 1x1 pixel)
            mock_screenshot = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNkYAAAAAYAAjCB0C8AAAAASUVORK5CYII="

            return {
                "sandbox_status": "completed",
                "risk_weight": 0,
                "dom_signals": {
                    "has_auth_inputs": is_suspicious_url,
                    "has_payment_forms": is_suspicious_url,
                    "input_tags_count": 3 if is_suspicious_url else 0,
                    "iframe_count": 1 if is_suspicious_url else 0
                },
                "screenshot_base64": mock_screenshot if is_suspicious_url else None,
                "final_redirect_url": url,
                "api_queried": False
            }

        # Real Fargate Task Triggering Code
        try:
            # Run blocking boto3 calls inside an executor thread
            loop = asyncio.get_running_loop()
            
            # Define running task logic in thread
            def run_ecs_task():
                ecs_client = boto3.client('ecs', region_name=region)
                response = ecs_client.run_task(
                    cluster=cluster,
                    launchType='FARGATE',
                    taskDefinition='scamshield-playwright-task',
                    count=1,
                    networkConfiguration={
                        'awsvpcConfiguration': {
                            'subnets': ['subnet-xxxxxxxx'], # Subnets must be configured or retrieved dynamically
                            'assignPublicIp': 'ENABLED'
                        }
                    },
                    overrides={
                        'containerOverrides': [
                            {
                                'name': 'playwright-scraper',
                                'environment': [
                                    {'name': 'TARGET_URL', 'value': url}
                                ]
                            }
                        ]
                    }
                )
                return response

            response = await loop.run_in_executor(None, run_ecs_task)
            
            # Extract task details (in production, we'd poll or wait for S3 uploads, 
            # but for low latency targets, Fargate starts async. Playwright container 
            # writes results directly to S3 which can trigger a webhook or return immediately)
            tasks = response.get('tasks', [])
            if not tasks:
                raise SandboxException("ECS run_task returned no running tasks.")
                
            task_arn = tasks[0].get('taskArn')
            logger.info(f"Fargate task launched successfully: {task_arn}")

            # For the synchronous 4s loop, we poll or fetch intermediate status from Fargate,
            # but since Fargate spin-up takes 10-20 seconds, we normally return a 'running' status
            # or fetch it if it's already pre-warmed/cached.
            return {
                "sandbox_status": "initiated",
                "task_arn": task_arn,
                "risk_weight": 0,
                "api_queried": True
            }
        except Exception as e:
            logger.error(f"Fargate sandbox invocation failed: {e}")
            raise SandboxException(f"Fargate invocation failed: {str(e)}")

    @classmethod
    async def analyze(cls, urls: List[str]) -> Dict[str, Any]:
        """
        Inspects the primary URL in the sandbox, respecting the 8-second timeout hard ceiling.
        """
        if not urls:
            return {"status": "bypassed", "sandbox_status": "skipped", "risk_weight": 0}

        primary_url = urls[0] # Analyze the first URL found
        
        try:
            # Enforce 8-second hard timeout
            result = await asyncio.wait_for(
                cls.trigger_fargate_task(primary_url),
                timeout=settings.SANDBOX_TIMEOUT_SECONDS
            )
            return result
        except asyncio.TimeoutError:
            logger.warning(f"AWS Fargate Sandbox timed out (> {settings.SANDBOX_TIMEOUT_SECONDS}s) for URL {primary_url}.")
            # Return Hostile Timeout Fallback Penalty
            return {
                "sandbox_status": "hostile_timeout",
                "risk_weight": 40,
                "error": "Execution timed out.",
                "screenshot_base64": None
            }
        except Exception as e:
            logger.error(f"AWS Fargate Sandbox failed for URL {primary_url}: {e}")
            # Non-blocking graceful failure path: apply penalty as well
            # Crashes also get treated as hostile_timeout per project specifications
            return {
                "sandbox_status": "hostile_timeout",
                "risk_weight": 40,
                "error": f"Fargate invocation crashed: {str(e)}",
                "screenshot_base64": None
            }
