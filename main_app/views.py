from django.shortcuts import render, redirect, get_object_or_404
from main_app.models import ThreatLog, ThreatCategory
from threat_monitoring.models import ThreatLog as MonitoringLog
from dark_web_monitoring.models import DarkWebAlert
from ai_module.models.predict import predict_threat
from django.db.models import Q
from django.contrib.auth.decorators import login_required
from ai_module.cyber_guru import cyber_guru
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from asgiref.sync import sync_to_async
import json
from django.utils import timezone

@login_required(login_url='/authentication/login/')
def dashboard(request):
    """Displays an overview of all monitoring sections."""
    try:
        # Main app threats
        main_threats = ThreatLog.objects.all().order_by('-timestamp')[:5]
        categories = ThreatCategory.objects.all()
        
        # Threat monitoring data
        monitoring_threats = MonitoringLog.objects.all().order_by('-timestamp')[:5]
        
        # Dark web alerts
        dark_web_alerts = DarkWebAlert.objects.all().order_by('-timestamp')[:5]
        
        context = {
            'main_threats': main_threats,
            'categories': categories,
            'monitoring_threats': monitoring_threats,
            'dark_web_alerts': dark_web_alerts,
        }
        return render(request, 'main_app/dashboard.html', context)
    except Exception as e:
        # Log the error for debugging
        print(f"Dashboard Error: {str(e)}")
        return render(request, 'main_app/dashboard.html', {
            'main_threats': [],
            'categories': [],
            'monitoring_threats': [],
            'dark_web_alerts': [],
            'error': 'An error occurred while loading the dashboard.'
        })

@login_required(login_url='/authentication/login/')
def threats(request):
    """Render the threat analysis page."""
    try:
        # Get recent threats
        threats = ThreatLog.objects.all().order_by('-timestamp')[:10]
        return render(request, 'main_app/threats.html', {'threats': threats})
    except Exception as e:
        print(f"Threats Error: {str(e)}")
        return render(request, 'main_app/threats.html', {
            'threats': [],
            'error': 'An error occurred while loading threat analysis results.'
        })

@login_required(login_url='/authentication/login/')
def analyze_logs(request):
    """Processes user-submitted IP addresses and predicts threats."""
    if request.method == "POST":
        ip = request.POST.get('ip')
        if not ip:
            return render(request, 'main_app/threats.html', {'error': 'Invalid IP entered.'})

        try:
            threat_type, confidence = predict_threat(ip)
            # Get or create the threat category
            category, _ = ThreatCategory.objects.get_or_create(
                name=threat_type,
                defaults={'description': f'Automatically detected {threat_type} threat'}
            )
            
            # Create the threat log
            threat = ThreatLog.objects.create(
                ip_address=ip,
                threat_type=category,
                confidence_score=confidence * 100,  # Convert to percentage
                status='active'
            )
            
            # Get recent threats for display
            threats = ThreatLog.objects.all().order_by('-timestamp')[:10]
            
            return render(request, 'main_app/threats.html', {
                'threats': threats,
                'success': f'Successfully analyzed IP: {ip}'
            })
        except Exception as e:
            print(f"Analysis Error: {str(e)}")
            return render(request, 'main_app/threats.html', {
                'error': f'Error analyzing IP: {str(e)}'
            })
    return redirect('threats')

@login_required
@csrf_exempt
async def chat_with_guru(request):
    if request.method == 'POST':
        try:
            # Print the raw request body for debugging
            print("Raw request body:", request.body)
            
            data = json.loads(request.body)
            user_message = data.get('message', '')
            
            # Print the parsed data for debugging
            print("Parsed data:", data)
            print("User message:", user_message)
            
            if not user_message:
                return JsonResponse({
                    'status': 'error',
                    'message': 'No message provided'
                }, status=400)
            
            # Get chat history from session
            chat_history = request.session.get('chat_history', [])
            
            # Add user message to history
            chat_history.append({
                'role': 'user',
                'content': user_message,
                'timestamp': timezone.now().isoformat()
            })
            
            # Get AI response
            response = await cyber_guru.get_response(user_message)
            print("Guru response:", response)
            
            # Add AI response to history
            chat_history.append({
                'role': 'assistant',
                'content': response,
                'timestamp': timezone.now().isoformat()
            })
            
            # Update session with new history
            request.session['chat_history'] = chat_history
            
            return JsonResponse({
                'status': 'success',
                'response': response
            })
            
        except json.JSONDecodeError as e:
            print("JSON Decode Error:", str(e))
            return JsonResponse({
                'status': 'error',
                'message': 'Invalid JSON data'
            }, status=400)
        except Exception as e:
            print("General Error:", str(e))
            return JsonResponse({
                'status': 'error',
                'message': str(e)
            }, status=500)
    
    # For GET requests, render the chat interface with history
    chat_history = request.session.get('chat_history', [])
    render_sync = sync_to_async(render, thread_sensitive=True)
    return await render_sync(request, 'main_app/cyber_guru.html', {
        'chat_history': chat_history
    })
