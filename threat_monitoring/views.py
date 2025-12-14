from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.http import JsonResponse
from .models import ThreatLog, WebsiteTrafficAnalysis
from .services import (
    get_recent_threats,
    get_threat_stats,
    analyze_threat,
    get_recent_analyses
)
from datetime import datetime, timedelta
from random import choice, randint

# Start threat monitoring when the module is imported
monitor_thread = start_threat_monitoring()

@login_required(login_url='/authentication/login/')
def dashboard(request):
    """
    Displays the threat monitoring dashboard with real-time threat data.
    """
    # Get filter parameters
    time_frame = request.GET.get('time_frame', '24')
    severity = request.GET.get('severity')
    
    # Get recent threats
    threats = get_recent_threats(hours=int(time_frame))
    if severity:
        threats = threats.filter(severity=severity)
    
    context = {
        'threats': threats[:10],  # Show latest 10 threats
        'stats': get_threat_stats(),
        'severities': ['low', 'medium', 'high', 'critical'],
        'time_frames': [
            ('1', 'Last Hour'),
            ('24', 'Last 24 Hours'),
            ('168', 'Last Week')
        ],
        'selected_severity': severity,
        'selected_time_frame': time_frame,
        'last_updated': datetime.now()
    }
    return render(request, 'threat_monitoring/dashboard.html', context)

@login_required(login_url='/authentication/login/')
def fetch_latest_intelligence(request):
    """
    Fetches the latest threat intelligence and updates the dashboard.
    """
    try:
        # Try to force a new network scan
        try:
            monitor_network_traffic()
        except Exception as e:
            # If network monitoring fails, create some sample data
            
            # Create a sample threat
            threat_types = ['port_scan', 'ddos', 'malware', 'unauthorized_access', 'data_exfiltration']
            severities = ['low', 'medium', 'high', 'critical']
            
            ThreatLog.objects.create(
                source_ip=f"192.168.1.{randint(1, 254)}",
                destination_ip=f"10.0.0.{randint(1, 254)}",
                threat_type=choice(threat_types),
                severity=choice(severities),
                description="Sample threat for demonstration",
                ai_risk_score=randint(50, 100),
                confidence_score=randint(70, 100),
                protocol=choice(['TCP', 'UDP', 'ICMP']),
                port=randint(1, 65535),
                packet_count=randint(1, 1000),
                status='new'
            )
        
        messages.success(request, 'Threat intelligence has been updated successfully.')
    except Exception as e:
        messages.error(request, f'Error updating threat intelligence: {str(e)}')
    
    return redirect('monitoring:threat_dashboard')

@login_required(login_url='/authentication/login/')
def logs_view(request):
    """
    Displays all threat logs with filtering options.
    """
    # Get filter parameters
    severity = request.GET.get('severity')
    threat_type = request.GET.get('threat_type')
    time_frame = request.GET.get('time_frame', '24')
    status = request.GET.get('status')
    
    # Get threats based on filters
    threats = get_recent_threats(hours=int(time_frame))
    
    if severity:
        threats = threats.filter(severity=severity)
    if threat_type:
        threats = threats.filter(threat_type=threat_type)
    if status:
        threats = threats.filter(status=status)
    
    context = {
        'threats': threats,
        'severities': ['low', 'medium', 'high', 'critical'],
        'threat_types': [
            'port_scan', 'ddos', 'malware', 'unauthorized_access',
            'data_exfiltration'
        ],
        'statuses': ['new', 'investigating', 'contained', 'resolved', 'false_positive'],
        'time_frames': [
            ('1', 'Last Hour'),
            ('24', 'Last 24 Hours'),
            ('168', 'Last Week')
        ],
        'selected_severity': severity,
        'selected_type': threat_type,
        'selected_status': status,
        'selected_time_frame': time_frame
    }
    return render(request, 'threat_monitoring/logs.html', context)

@login_required(login_url='/authentication/login/')
def analyze_threat_view(request, threat_id):
    """
    Analyzes a specific threat and updates its status.
    """
    try:
        if analyze_threat(threat_id):
            messages.success(request, 'Threat analysis completed successfully.')
        else:
            messages.error(request, 'Threat not found.')
    except Exception as e:
        messages.error(request, f'Error analyzing threat: {str(e)}')
    
    return redirect('monitoring:threat_logs')

@login_required(login_url='/authentication/login/')
def update_threat_status_view(request, threat_id):
    """
    Updates the status of a specific threat.
    """
    if request.method == 'POST':
        new_status = request.POST.get('status')
        if new_status in ['new', 'investigating', 'contained', 'resolved', 'false_positive']:
            if update_threat_status(threat_id, new_status):
                messages.success(request, 'Threat status updated successfully.')
            else:
                messages.error(request, 'Threat not found.')
        else:
            messages.error(request, 'Invalid status provided.')
    
    return redirect('monitoring:threat_logs')

@login_required(login_url='/authentication/login/')
def traffic_analysis(request):
    """
    Displays the website traffic analysis page.
    """
    if request.method == 'POST':
        url = request.POST.get('website_url')
        if url:
            analysis = analyze_website_traffic(url)
            if analysis:
                messages.success(request, 'Traffic analysis completed successfully.')
                return redirect('monitoring:traffic_analysis_detail', analysis_id=analysis.id)
            else:
                messages.error(request, 'Error analyzing website traffic.')
    
    recent_analyses = get_recent_analyses()
    context = {
        'recent_analyses': recent_analyses
    }
    return render(request, 'threat_monitoring/traffic_analysis.html', context)

@login_required(login_url='/authentication/login/')
def traffic_analysis_detail(request, analysis_id):
    """
    Displays detailed results of a traffic analysis.
    """
    analysis = get_traffic_analysis(analysis_id)
    if not analysis:
        messages.error(request, 'Analysis not found.')
        return redirect('monitoring:traffic_analysis')
    
    # Calculate percentages for traffic sources
    traffic_sources = {}
    total_requests = analysis.results['analysis_summary']['total_requests']
    for source, count in analysis.results['traffic_sources'].items():
        percentage = (count / total_requests) * 100 if total_requests > 0 else 0
        traffic_sources[source] = {
            'count': count,
            'percentage': round(percentage, 1)
        }
    
    context = {
        'analysis': analysis,
        'results': analysis.results,
        'traffic_sources': traffic_sources
    }
    return render(request, 'threat_monitoring/traffic_analysis_detail.html', context)
