import unittest
from unittest.mock import patch, Mock
import helper
from core import network

class RouteTests(unittest.TestCase):
    def setUp(self):
        helper.SESSIONS.clear()
        self.s={'owned':[], 'dev':'utun8','reserved':[], 'peers':['198.51.100.2']}
    def test_transport_cannot_be_routed_into_itself(self):
        with patch.object(helper,'run') as run, self.assertRaises(ValueError):
            helper.add_route(self.s,network('198.51.100.0/24'))
        run.assert_not_called()
    def test_broad_destination_excludes_only_transport_hosts(self):
        import ipaddress
        original=network('198.51.0.0/16')
        peers=['198.51.100.2','198.51.101.7']
        routes=helper.transport_safe_routes([original],peers)
        self.assertEqual(sum(n.num_addresses for n in routes),original.num_addresses-2)
        for peer in peers:
            self.assertFalse(any(ipaddress.IPv4Address(peer) in n for n in routes))
        self.assertTrue(all(n.subnet_of(original) for n in routes))
        self.assertEqual(helper.transport_safe_routes([network('10.2.0.0/16')],peers),[network('10.2.0.0/16')])
    def test_explicit_transport_destination_still_rejected(self):
        with self.assertRaisesRegex(ValueError,'transport endpoint'):
            helper.transport_safe_routes([network('198.51.100.2/32')],['198.51.100.2'])

    def test_existing_system_route_is_not_replaced(self):
        with patch.object(helper,'run',return_value=Mock(stdout='destination: 10.1.0.0\ninterface: en0\n')), patch.object(helper,'route') as route:
            with self.assertRaises(ValueError): helper.add_route(self.s,network('10.1.0.0/16'))
            route.assert_not_called()
    def test_failed_add_is_not_owned(self):
        with patch.object(helper,'run',return_value=Mock(stdout='destination: default\ninterface: en0\n')), patch.object(helper,'route',return_value=Mock(returncode=1,stderr='exists')):
            with self.assertRaises(RuntimeError): helper.add_route(self.s,network('10.1.0.0/16'))
        self.assertEqual(self.s['owned'],[])
    def test_cleanup_does_not_delete_route_reassigned_to_other_vpn(self):
        self.s['owned']=[network('10.1.0.0/16')]
        with patch.object(helper,'run',return_value=Mock(stdout='interface: utun9\n')),patch.object(helper,'route') as route:
            helper.remove_routes(self.s); route.assert_not_called()
        self.assertEqual(self.s['owned'],[])
    def test_dns_host_route_inside_own_subnet(self):
        with patch.object(helper,'run',return_value=Mock(stdout='destination: 10.1.0.0\ninterface: utun8\n')),patch.object(helper,'route',return_value=Mock(returncode=0)):
            helper.add_route(self.s,network('10.1.2.3/32'))
        self.assertEqual(self.s['owned'],[network('10.1.2.3/32')])

class DispatchTests(unittest.TestCase):
    def test_ten_sessions_start_with_isolated_key_and_eleventh_is_rejected(self):
        import pathlib,tempfile,threading
        from tests_base import PROFILE
        with tempfile.TemporaryDirectory() as tmp, patch.dict(helper.SESSIONS,{},clear=True),patch.dict(helper.DIRECT,{'cidrs':[],'domains':[]},clear=True),patch.object(helper,'ROOT',tmp),patch.object(helper,'BINARY','/opt/homebrew/sbin/openvpn',create=True),patch.object(helper.subprocess,'Popen') as spawn,patch.object(helper,'Bridge') as bridge,patch.object(helper.threading,'Thread'):
            spawn.return_value.poll.return_value=None
            for i in range(10):
                helper.dispatch(dict(op='connect',name='project'+str(i),profile=PROFILE,domains=['*.p'+str(i)+'.example.com'],cidrs=[],dns='',credentials=dict(username='alice',password='test-only',mode='password'),key_password='dummy-key-pass'))
            self.assertEqual(len(helper.SESSIONS),10)
            self.assertEqual(bridge.call_args.args[-1],'dummy-key-pass')
            args=spawn.call_args.args[0]
            self.assertIn('--route-nopull',args)
            self.assertIn('--route-noexec',args)
            self.assertNotIn('test-only',args)
            self.assertNotIn('dummy-key-pass',args)
            with self.assertRaisesRegex(ValueError,'Maximum 10'):
                helper.dispatch(dict(op='connect',name='eleventh'))

    def test_direct_edit_rejected_while_any_tunnel_is_running(self):
        process=Mock();process.poll.return_value=None
        with patch.dict(helper.SESSIONS,{'active':{'process':process}},clear=True):
            with self.assertRaisesRegex(ValueError,'Disconnect'):
                helper.dispatch(dict(op='direct-rules',cidrs=[],domains=['*.example.com']))

class CleanupTests(unittest.TestCase):
    def test_changed_resolver_does_not_prevent_child_termination(self):
        process=Mock();process.poll.return_value=None
        session=dict(process=process,owned=[],dev='utun8',bridge=Mock(),state='connected')
        with patch.object(helper,'sync_resolvers',side_effect=RuntimeError('resolver edited')),patch.object(helper,'remove_routes') as remove:
            with self.assertRaisesRegex(RuntimeError,'resolver edited'):helper.disconnect(session)
            process.terminate.assert_called_once();remove.assert_called_once()
            self.assertTrue(session['stopping'])


class ForgetTests(unittest.TestCase):
    def test_removing_one_stopped_profile_leaves_other_sessions(self):
        stopped=Mock();stopped.poll.return_value=0
        active=Mock();active.poll.return_value=None
        with patch.dict(helper.SESSIONS,{'one':dict(process=stopped,owned=[],stopping=True),'two':dict(process=active,owned=[],stopping=False)},clear=True),patch.object(helper,'sync_resolvers'):
            helper.dispatch({'op':'forget','name':'one'})
            self.assertNotIn('one',helper.SESSIONS)
            self.assertIn('two',helper.SESSIONS)
            with self.assertRaisesRegex(ValueError,'Disconnect'):helper.dispatch({'op':'forget','name':'two'})
            self.assertIn('two',helper.SESSIONS)
    def test_forget_refuses_outstanding_cleanup(self):
        process=Mock();process.poll.return_value=0
        with patch.dict(helper.SESSIONS,{'one':dict(process=process,owned=[network('10.20.0.0/16')],stopping=True)},clear=True):
            with self.assertRaisesRegex(ValueError,'cleanup'):helper.dispatch({'op':'forget','name':'one'})
            self.assertIn('one',helper.SESSIONS)


class CacheWarmupTests(unittest.TestCase):
    def test_only_explicit_domains_are_warmed_and_suffixes_are_not_guessed(self):
        session={'domains':['*.example.com','stage.example.com'],'stopping':False}
        with patch.object(helper,'resolve_domain') as query:
            helper.warm_domains(session)
            self.assertEqual(query.call_count,1)
            self.assertEqual(query.call_args.args[1],'stage.example.com')
