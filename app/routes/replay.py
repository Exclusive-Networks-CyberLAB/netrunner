"""
NetRunner OS - Replay Routes
"""

import threading
from flask import Blueprint, request, jsonify, current_app, Response
from app.core.engine import replay_pcap_task, active_task_status
import json
import time

bp = Blueprint('replay', __name__)


@bp.route('/replay/start', methods=['POST'])
def start_replay():
    """Start replaying a PCAP file with optional rewrite rules."""
    if active_task_status['is_running']:
        return jsonify({'error': 'A task is already running.'}), 400

    try:
        data = request.get_json()
        filepath = data.get('filepath') or current_app.config.get('LAST_PCAP')
        if not filepath:
            return jsonify({'error': 'No PCAP file loaded. Please upload one first.'}), 400

        import os
        if not os.path.exists(filepath):
            return jsonify({'error': 'PCAP file not found.'}), 400

        params = {
            'filepath': filepath,
            'interface': data.get('interface', 'eth0'),
            'replay_speed': data.get('speed', 'original'),
            'loop_replay': data.get('loop', False),
            'loop_count': int(data.get('loop_count', 0)),
            'ttl': int(data['ttl']) if data.get('ttl') else None,
            'vlan_id': int(data['vlan_id']) if data.get('vlan_id') else None,
            'ip_map': data.get('ip_map', {}),
            'mac_map': data.get('mac_map', {}),
            'port_map': data.get('port_map', {})
        }

        # Reset state
        active_task_status['is_running'] = True
        active_task_status['task_type'] = 'replay'
        active_task_status['progress'] = 0
        active_task_status['total'] = 0
        active_task_status['loop_count'] = 0
        active_task_status['packets_per_second'] = 0
        active_task_status['message'] = 'Initializing replay...'
        active_task_status['error'] = None
        active_task_status['logs'].clear()

        thread = threading.Thread(target=replay_pcap_task, args=(params,), daemon=True)
        thread.start()

        return jsonify({'status': 'Replay started.'})

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@bp.route('/replay/stop', methods=['POST'])
def stop_replay():
    """Stop the active replay."""
    active_task_status['is_running'] = False
    return jsonify({'status': 'Stop signal sent.'})


@bp.route('/replay/status')
def replay_status():
    """SSE stream for real-time replay status."""
    def generate():
        while True:
            data = {
                'is_running': active_task_status['is_running'],
                'task_type': active_task_status['task_type'],
                'message': active_task_status['message'],
                'progress': active_task_status['progress'],
                'total': active_task_status['total'],
                'loop_count': active_task_status['loop_count'],
                'pps': active_task_status['packets_per_second'],
                'error': active_task_status['error'],
                'logs': list(active_task_status['logs'])
            }
            yield f"data: {json.dumps(data)}\n\n"

            if not active_task_status['is_running'] and active_task_status['task_type'] is not None:
                # Send one final update then stop
                yield f"data: {json.dumps(data)}\n\n"
                break

            time.sleep(0.5)

    return Response(generate(), mimetype='text/event-stream',
                    headers={'Cache-Control': 'no-cache', 'X-Accel-Buffering': 'no'})
