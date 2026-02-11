"""
NetRunner OS - Traffic Generator Routes
"""

import threading
from flask import Blueprint, request, jsonify
from app.core.engine import active_task_status
from app.core.generators import protocol, adversary

bp = Blueprint('generator', __name__)


@bp.route('/generate/protocol', methods=['POST'])
def generate_protocol():
    """Generate realistic protocol traffic."""
    if active_task_status['is_running']:
        return jsonify({'error': 'A task is already running.'}), 400

    try:
        data = request.get_json()
        proto = data.get('protocol', 'dns')
        interface = data.get('interface', 'eth0')

        # Reset state
        active_task_status['is_running'] = True
        active_task_status['task_type'] = 'generate'
        active_task_status['progress'] = 0
        active_task_status['total'] = 0
        active_task_status['message'] = f'Generating {proto.upper()} traffic...'
        active_task_status['error'] = None
        active_task_status['logs'].clear()

        params = {
            'interface': interface,
            'protocol': proto,
            'src_ip': data.get('src_ip', '10.0.0.100'),
            'dst_ip': data.get('dst_ip', '10.0.0.1'),
            'src_mac': data.get('src_mac'),
            'dst_mac': data.get('dst_mac', 'ff:ff:ff:ff:ff:ff'),
            'count': int(data.get('count', 10)),
            'delay': float(data.get('delay', 0.5)),
            'domain': data.get('domain', 'example.com'),
            'payload': data.get('payload', ''),
        }

        thread = threading.Thread(
            target=protocol.generate,
            args=(params,),
            daemon=True
        )
        thread.start()
        return jsonify({'status': f'{proto.upper()} generation started.'})

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@bp.route('/generate/adversary', methods=['POST'])
def generate_adversary():
    """Generate adversary simulation traffic."""
    if active_task_status['is_running']:
        return jsonify({'error': 'A task is already running.'}), 400

    try:
        data = request.get_json()
        sim_type = data.get('simulation', 'c2_beacon')
        interface = data.get('interface', 'eth0')

        # Reset state
        active_task_status['is_running'] = True
        active_task_status['task_type'] = 'generate'
        active_task_status['progress'] = 0
        active_task_status['total'] = 0
        active_task_status['message'] = f'Running {sim_type} simulation...'
        active_task_status['error'] = None
        active_task_status['logs'].clear()

        params = {
            'interface': interface,
            'simulation': sim_type,
            'src_ip': data.get('src_ip', '10.0.0.100'),
            'dst_ip': data.get('dst_ip', '10.0.0.1'),
            'c2_host': data.get('c2_host', '185.100.87.42'),
            'src_mac': data.get('src_mac'),
            'dst_mac': data.get('dst_mac', 'ff:ff:ff:ff:ff:ff'),
            'count': int(data.get('count', 50)),
            'delay': float(data.get('delay', 1.0)),
            'domain': data.get('domain', 'evil-c2.xyz'),
            'duration': int(data.get('duration', 60)),
        }

        thread = threading.Thread(
            target=adversary.generate,
            args=(params,),
            daemon=True
        )
        thread.start()
        return jsonify({'status': f'{sim_type} simulation started.'})

    except Exception as e:
        return jsonify({'error': str(e)}), 500
