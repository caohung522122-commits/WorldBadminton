// =============================================================
// WORLD BADMINTON - CLOUDFLARE WORKER
// Xác thực GitHub, phân quyền quản trị và lưu dữ liệu website.
// =============================================================

// PHẦN 1 - CORS: giới hạn website được phép gọi API.
const corsHeaders = (origin, env) => ({
  "Access-Control-Allow-Origin": env.SITE_ORIGIN,
  "Access-Control-Allow-Credentials": "true",
  "Access-Control-Allow-Methods": "GET, POST, PUT, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type",
  "Vary": "Origin"
});

// PHẦN 2 - HÀM TRẢ VỀ JSON cho website.
const json = (data, status=200, origin, env) => new Response(JSON.stringify(data), {status, headers:{"Content-Type":"application/json; charset=utf-8", ...corsHeaders(origin,env)}});

// PHẦN 3 - COOKIE BẢO MẬT: HttpOnly và Secure.
const cookie = (name,value,maxAge) => `${name}=${value}; HttpOnly; Secure; SameSite=None; Partitioned; Path=/; Max-Age=${maxAge}`;

// PHẦN 4 - TẠO MÃ NGẪU NHIÊN cho state và phiên đăng nhập.
const random = (n=32) => { const b=new Uint8Array(n); crypto.getRandomValues(b); return [...b].map(x=>x.toString(16).padStart(2,'0')).join(''); };

// PHẦN 5 - KIỂM TRA PHIÊN đăng nhập trong Cloudflare KV.
async function getSession(request,env){const raw=request.headers.get('Cookie')||'';const m=raw.match(/(?:^|;\s*)shine_session=([a-f0-9]+)/);if(!m)return null;return await env.WORLD_KV.get('session:'+m[1],'json');}

// PHẦN 6 - KIỂM TRA WEBSITE GỬI YÊU CẦU.
function allowedOrigin(request,env){return request.headers.get('Origin')===env.SITE_ORIGIN;}

// PHẦN 7 - BỘ XỬ LÝ CHÍNH của Cloudflare Worker.
export default {
 async fetch(request,env){
  const url=new URL(request.url), origin=request.headers.get('Origin');
  if(request.method==='OPTIONS'){if(!allowedOrigin(request,env))return new Response(null,{status:403});return new Response(null,{headers:corsHeaders(origin,env)});}

  // PHẦN 7.1 - ĐĂNG NHẬP: chuyển người dùng sang GitHub OAuth.
  if(url.pathname==='/auth/login'){
   const state=random(24);await env.WORLD_KV.put('oauth:'+state,'1',{expirationTtl:600});
   const redirect=`https://github.com/login/oauth/authorize?client_id=${encodeURIComponent(env.GITHUB_CLIENT_ID)}&redirect_uri=${encodeURIComponent(env.GITHUB_CALLBACK_URL)}&scope=read:user&state=${state}`;
   return Response.redirect(redirect,302);
  }

  // PHẦN 7.2 - CALLBACK: xác minh tài khoản GitHub và quyền quản trị.
  if(url.pathname==='/auth/callback'){
   const code=url.searchParams.get('code'),state=url.searchParams.get('state');
   if(!code||!state||!await env.WORLD_KV.get('oauth:'+state))return new Response('Phiên đăng nhập không hợp lệ.',{status:400});
   await env.WORLD_KV.delete('oauth:'+state);
   const tokenRes=await fetch('https://github.com/login/oauth/access_token',{method:'POST',headers:{Accept:'application/json','Content-Type':'application/json'},body:JSON.stringify({client_id:env.GITHUB_CLIENT_ID,client_secret:env.GITHUB_CLIENT_SECRET,code,redirect_uri:env.GITHUB_CALLBACK_URL})});
   const token=await tokenRes.json();if(!token.access_token)return new Response('Không thể xác thực GitHub.',{status:401});
   const userRes=await fetch('https://api.github.com/user',{headers:{Authorization:`Bearer ${token.access_token}`,Accept:'application/vnd.github+json','User-Agent':'World-Badminton-Admin'}});const user=await userRes.json();
   if(!user.login||user.login.toLowerCase()!==String(env.ADMIN_GITHUB_USERNAME||'').toLowerCase())return Response.redirect(env.SITE_ORIGIN+'/?admin=denied',302);
   const sid=random(32);await env.WORLD_KV.put('session:'+sid,JSON.stringify({login:user.login}),{expirationTtl:604800});
   return new Response(null,{status:302,headers:{Location:env.SITE_ORIGIN+'/', 'Set-Cookie':cookie('shine_session',sid,604800),'Cache-Control':'no-store'}});
  }

  // PHẦN 7.3 - ĐĂNG XUẤT: hủy phiên quản trị.
  if(url.pathname==='/auth/logout'&&request.method==='POST'){
   if(!allowedOrigin(request,env))return json({error:'Origin không hợp lệ'},403,origin,env);
   const session=await getSession(request,env);const raw=request.headers.get('Cookie')||'';const m=raw.match(/(?:^|;\s*)shine_session=([a-f0-9]+)/);if(m)await env.WORLD_KV.delete('session:'+m[1]);
   return new Response(JSON.stringify({ok:true}),{headers:{'Content-Type':'application/json',...corsHeaders(origin,env),'Set-Cookie':cookie('shine_session','',0)}});
  }

  // PHẦN 7.4 - API DỮ LIỆU: đọc trạng thái, tải và lưu dữ liệu.
  if(url.pathname.startsWith('/api/')){
   if(!allowedOrigin(request,env))return json({error:'Origin không hợp lệ'},403,origin,env);
   if(url.pathname==='/api/me'&&request.method==='GET'){const s=await getSession(request,env);return json({user:s?.login||null},200,origin,env);}
   if(url.pathname==='/api/data'&&request.method==='GET'){const data=await env.WORLD_KV.get('site:data','json');return json({data:data||null},200,origin,env);}
   if(url.pathname==='/api/data'&&request.method==='PUT'){
    const s=await getSession(request,env);if(!s||s.login.toLowerCase()!==String(env.ADMIN_GITHUB_USERNAME||'').toLowerCase())return json({error:'Bạn không có quyền quản trị.'},401,origin,env);
    const len=Number(request.headers.get('Content-Length')||0);if(len>8_000_000)return json({error:'Dữ liệu quá lớn. Hãy giảm dung lượng ảnh.'},413,origin,env);
    let data;try{data=await request.json()}catch(e){return json({error:'Dữ liệu không hợp lệ.'},400,origin,env)}
    if(!data||!Array.isArray(data.athletes)||!Array.isArray(data.popular)||!Array.isArray(data.beginner))return json({error:'Thiếu dữ liệu.'},400,origin,env);
    await env.WORLD_KV.put('site:data',JSON.stringify(data));return json({ok:true},200,origin,env);
   }
  }
  return new Response('Not found',{status:404});
 }
};