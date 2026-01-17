async function fetchWorkers(){
  const res = await fetch('/api/workers');
  const list = await res.json();
  const tbody = document.querySelector('#workers tbody');
  tbody.innerHTML = '';
  for(const w of list){
    const tr = document.createElement('tr');
    tr.innerHTML = `<td>${w.id}</td><td>${w.name}</td><td>${w.ip}:${w.port}</td><td>${w.cidr}</td><td><button data-id='${w.id}' class='btn-status'>Status</button></td>`;
    tbody.appendChild(tr);
  }
  document.querySelectorAll('.btn-status').forEach(b=>b.addEventListener('click', async (e)=>{
    const id = e.target.getAttribute('data-id');
    e.target.textContent = 'Loading...';
    const r = await fetch(`/api/workers/status?id=${id}`);
    const txt = await r.text();
    alert(txt);
    e.target.textContent = 'Status';
  }));
}

document.getElementById('addForm').addEventListener('submit', async (ev)=>{
  ev.preventDefault();
  const form = ev.target;
  const data = Object.fromEntries(new FormData(form).entries());
  data.port = parseInt(data.port,10);
  const res = await fetch('/api/workers',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(data)});
  if(res.status===201){
    document.getElementById('msg').textContent = 'Worker hinzugefügt.';
    form.reset();
    fetchWorkers();
  } else {
    const t = await res.text();
    document.getElementById('msg').textContent = 'Fehler: '+t;
  }
});

fetchWorkers();