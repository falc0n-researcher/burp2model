window.AdminPanel = ({api, Link, h, useState, useEffect}) => { const [u, setU] = useState([]), [s, setS] = useState(null), [err, setErr] = useState('');
  useEffect(() => { api('/admin/users').then(setU).catch(e => setErr(String(e.message))); api('/admin/stats').then(setS).catch(() => {}); }, []);
  return h('div', null, h('h1', null, 'Admin'), err && h('p', null, err), s && h('p', null, 'Users: ' + s.users), u.map(x => h('div', {key: x.id}, h('button', {onClick: () => api('/admin/users/' + x.id).then(() => {})}, 'Inspect ' + x.email)))); };
