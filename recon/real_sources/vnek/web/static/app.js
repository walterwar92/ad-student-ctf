const content=document.querySelector('#content');
const qs=s=>document.querySelector(s);
const esc=v=>String(v??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const encode=v=>encodeURIComponent(String(v));
const icon=name=>`<svg class="ui-icon" aria-hidden="true"><use href="#icon-${name}"></use></svg>`;
const avatar=(name,size='')=>`<span class="avatar ${size}">${esc((name||'?').trim().charAt(0).toUpperCase())}</span>`;
const form=data=>({method:'POST',body:new URLSearchParams(data)});
function registrationDate(value){
 const raw=String(value??'');
 const match=/^(\d{4}-\d{2}-\d{2})T(\d{2}:\d{2}:\d{2})(?:\.\d+)?Z$/.exec(raw);
 return match?`${match[1]} ${match[2]} UTC`:`${raw} UTC`;
}
let me=null,view='feed',peer='',profileName='',peopleCache=[],conversationsCache=[],generation=0,previewURL='',toastTimer=null,activeThread=null;
let notificationSocket=null,notificationTimer=null,notificationRetry=700,notificationStopped=true,notificationAudio=null;

async function api(url,options={}){
 const res=await fetch(url,{credentials:'same-origin',...options});
 const data=await res.json().catch(()=>({error:'Некорректный ответ сервера'}));
 if(!res.ok)throw new Error(data.error||`Ошибка ${res.status}`);
 return data;
}
function toast(text){const el=qs('#toast');el.textContent=text;el.classList.add('show');clearTimeout(toastTimer);toastTimer=setTimeout(()=>el.classList.remove('show'),2800)}
function notice(err){const el=qs('#notice');if(el)el.textContent=err.message||String(err);else toast(err.message||String(err))}
function blank(glyph,title,description){return `<div class="empty"><div class="empty-icon">${glyph}</div><b>${esc(title)}</b><p>${esc(description)}</p></div>`}
function setActive(){document.querySelectorAll('.nav-item[data-view]').forEach(el=>el.classList.toggle('active',el.dataset.view===view))}
function account(){qs('#header-account').innerHTML=me?`<button class="account-button" data-view="profile">${avatar(me.display)}<span>${esc(me.display)}</span></button>`:'Присоединяйся к нам'}
function signedIn(on){document.body.classList.toggle('signed-out',!on)}
async function refreshPeople(){peopleCache=await api('/api/users')}
// Browsers permit audio only after the user interacts with the page.
function unlockNotificationAudio(){
 try{
  if(!notificationAudio){
   const AudioContextType=window.AudioContext||window.webkitAudioContext;
   if(!AudioContextType)return;
   notificationAudio=new AudioContextType();
  }
  if(notificationAudio.state==='suspended')notificationAudio.resume().catch(()=>{});
 }catch(e){}
}
function playNotificationSound(){
 if(!notificationAudio||notificationAudio.state!=='running')return;
 try{
  const now=notificationAudio.currentTime;
  for(const [index,pitch] of [784,1046.5].entries()){
   const start=now+index*0.13;
   const oscillator=notificationAudio.createOscillator();
   const volume=notificationAudio.createGain();
   oscillator.type='sine';oscillator.frequency.setValueAtTime(pitch,start);
   volume.gain.setValueAtTime(0.001,start);
   volume.gain.exponentialRampToValueAtTime(0.055,start+0.012);
   volume.gain.exponentialRampToValueAtTime(0.001,start+0.23);
   oscillator.connect(volume);volume.connect(notificationAudio.destination);
   oscillator.start(start);oscillator.stop(start+0.24);
  }
 }catch(e){}
}
function stopNotifications(){
 notificationStopped=true;
 clearTimeout(notificationTimer);
 if(notificationSocket){notificationSocket.onclose=null;notificationSocket.close();notificationSocket=null}
}
function connectNotifications(){
 if(notificationStopped||!me)return;
 let socket;
 try{socket=new WebSocket(websocketURL())}
 catch(e){scheduleNotificationReconnect();return}
 notificationSocket=socket;
 socket.onopen=()=>{if(notificationSocket===socket)notificationRetry=700};
 socket.onmessage=e=>{
  if(notificationStopped||notificationSocket!==socket||!me)return;
  let event;try{event=JSON.parse(e.data)}catch{return}
  if(event.type!=='message'||!event.message)return;
  if(event.message.To===me.username&&event.message.From!==me.username)playNotificationSound();
  if(view==='messages')refreshConversations().catch(()=>{});
 };
 socket.onclose=()=>{
  if(notificationStopped||notificationSocket!==socket)return;
  notificationSocket=null;
  scheduleNotificationReconnect();
 };
}
function scheduleNotificationReconnect(){
 if(notificationStopped)return;
 const delay=notificationRetry;
 notificationRetry=Math.min(15000,Math.round(notificationRetry*1.8));
 clearTimeout(notificationTimer);
 notificationTimer=setTimeout(connectNotifications,delay);
}
function startNotifications(){
 stopNotifications();notificationStopped=false;notificationRetry=700;
 connectNotifications();
}
async function refreshConversations(){
 const run=generation;
 const users=await api('/api/conversations');
 if(view!=='messages'||generation!==run)return;
 conversationsCache=users;
 const el=qs('#contacts');
 if(el&&!el.classList.contains('search-open'))el.innerHTML=contactList(users,peer);
}
document.addEventListener('pointerdown',unlockNotificationAudio);
document.addEventListener('keydown',unlockNotificationAudio);
function stopThread(){
 const s=activeThread;if(!s)return;
 activeThread=null;
 clearTimeout(s.reconnectTimer);clearTimeout(s.pendingTimer);
 if(s.socket){s.socket.onclose=null;s.socket.close()}
}

async function boot(){
 try{me=await api('/api/me');signedIn(true);account();startNotifications();await navigate(view,peer||profileName)}
 catch(e){me=null;signedIn(false);account();showAuth('login');if(e.message!=='Требуется вход')toast(e.message)}
}
function showAuth(mode){
 stopThread();stopNotifications();view='auth';setActive();signedIn(false);
 const login=mode==='login';
 content.innerHTML=`<section class="card auth-wrapper"><div class="auth-promo"><div class="promo-icon">✦</div><h1>Самое интересное происходит здесь.</h1><p>Делись моментами, находи знакомых и оставайся на связи каждый день.</p><div class="promo-detail">ВнеКонтакта · Твоя маленькая социальная сеть</div></div><div class="auth-form"><h2>${login?'С возвращением!':'Создать страницу'}</h2><p>${login?'Войди в свой аккаунт, чтобы увидеть новости друзей.':'Всего пара шагов — и твоя страница готова.'}</p><form id="auth-form"><div class="field"><label for="username">Логин</label><input class="input" name="username" id="username" placeholder="например, alex_2026" pattern="[A-Za-z0-9_]{3,25}" maxlength="25" autocomplete="username" required></div><div class="field"><label for="password">Пароль</label><input class="input" id="password" name="password" type="password" minlength="6" maxlength="128" placeholder="Не меньше 6 символов" autocomplete="${login?'current-password':'new-password'}" required></div><div class="notice" id="notice"></div><button class="button" type="submit">${login?'Войти':'Зарегистрироваться'} →</button></form><div class="auth-switch">${login?'Ещё нет страницы?':'Уже есть аккаунт?'} <button data-auth="${login?'register':'login'}">${login?'Создать аккаунт':'Войти'}</button></div></div></section>`;
 qs('#auth-form').addEventListener('submit',async e=>{
  e.preventDefault();const b=e.submitter;b.disabled=true;
  try{await api('/api/'+mode,form(Object.fromEntries(new FormData(e.currentTarget))));view='feed';await boot();toast(login?'Рады снова видеть!':'Страница создана!')}
  catch(err){notice(err)}finally{b.disabled=false}
 });
}
async function logout(){
 try{await api('/api/logout',form({}));stopThread();stopNotifications();me=null;peer='';profileName='';showAuth('login');account();toast('Вы вышли из аккаунта')}
 catch(e){notice(e)}
}
async function navigate(next,arg=''){
 if(!me){showAuth('login');return}
 stopThread();view=next;setActive();const run=++generation;
 content.innerHTML='<section class="card loading">Загружаем страницу…</section>';
 try{
  if(run!==generation)return;
  if(next==='feed')await feed(run);
  else if(next==='profile')await profile(arg||me.username,run);
  else if(next==='settings')renderSettings();
  else if(next==='messages')await messages(arg||peer,run);
  else{view='feed';await feed(run)}
 }catch(e){if(run===generation)content.innerHTML=`<section class="card card-pad"><div class="notice">${esc(e.message)}</div><button class="button secondary" data-view="feed">Вернуться в новости</button></section>`}
}

function renderPost(p){
 return `<article class="card post-card"><div class="post-owner">${avatar(p.Display)}<div><button class="post-person" data-user="${esc(p.Author)}">${esc(p.Display)}</button><div class="post-date">${esc(p.Created)}</div></div></div>${p.Text?`<div class="post-copy">${esc(p.Text)}</div>`:''}${p.Photo?`<a href="${esc(p.Photo)}" target="_blank" rel="noopener noreferrer"><img loading="lazy" class="post-image" src="${esc(p.Photo)}" alt="Фотография из публикации"></a>`:''}<div class="post-foot"><button type="button" class="like-button ${p.Liked?'liked':''}" data-like="${esc(p.ID)}" data-liked="${Boolean(p.Liked)}" aria-pressed="${Boolean(p.Liked)}">${icon('heart')}<span>Нравится</span><span class="like-count">${Number(p.Likes)||0}</span></button></div></article>`;
}
async function toggleLike(button){
 if(!me||button.disabled)return;
 const liked=button.dataset.liked!=='true';button.disabled=true;
 try{
  const result=await api('/api/posts/like',form({id:button.dataset.like,liked:String(liked)}));
  if(!button.isConnected)return;
  button.dataset.liked=String(result.liked);
  button.setAttribute('aria-pressed',String(result.liked));
  button.classList.toggle('liked',result.liked);
  button.querySelector('.like-count').textContent=result.likes;
 }catch(err){toast(err.message)}finally{button.disabled=false}
}
async function feed(run){
 const posts=await api('/api/posts');if(run!==generation)return;
 content.innerHTML=`<section class="card"><div class="composer-top">${avatar(me.display)}<textarea class="textarea" maxlength="2000" id="post-text" name="text" form="post-form" placeholder="Что у вас нового?"></textarea></div><div id="photo-preview" class="photo-preview"></div><form id="post-form" class="composer-bottom"><label class="attach">${icon('image')} <span id="attach-label">Добавить изображение</span><input type="file" id="post-image" name="image" accept="image/png,image/jpeg,image/webp"></label><button class="button" type="submit">Опубликовать <span>→</span></button></form><div id="notice" class="notice" style="padding:0 22px"></div></section><div class="timeline-title">Свежие новости <span class="muted">· ${posts.length}</span></div>${posts.map(renderPost).join('')||`<section class="card">${blank(icon('feed'),'Лента пока пуста','Опубликуй первую запись — и здесь появятся новости.')}</section>`}`;
 qs('#post-image').addEventListener('change',e=>{
  if(previewURL)URL.revokeObjectURL(previewURL);
  const file=e.target.files[0];
  if(!file){qs('#photo-preview').classList.remove('visible');qs('#attach-label').textContent='Добавить изображение';return}
  if(file.size>5*1024*1024){e.target.value='';toast('Фотография должна быть меньше 5 МБ');return}
  previewURL=URL.createObjectURL(file);
  qs('#photo-preview').innerHTML=`<img src="${previewURL}" alt="Предпросмотр"><button type="button" class="preview-remove" id="remove-preview">✕ Убрать</button>`;
  qs('#photo-preview').classList.add('visible');qs('#attach-label').textContent=file.name;
  qs('#remove-preview').addEventListener('click',()=>{qs('#post-image').value='';qs('#photo-preview').classList.remove('visible');qs('#attach-label').textContent='Добавить изображение';URL.revokeObjectURL(previewURL);previewURL=''});
 });
 qs('#post-form').addEventListener('submit',async e=>{
  e.preventDefault();const image=qs('#post-image').files[0],text=qs('#post-text').value.trim();if(!text&&!image){toast('Добавь текст или фотографию');return}
  const b=e.submitter;b.disabled=true;b.textContent='Публикуем…';
  const data=new FormData();data.append('text',text);if(image)data.append('image',image);
  try{await api('/api/posts',{method:'POST',body:data});toast('Запись опубликована');await navigate('feed')}
  catch(err){notice(err);b.disabled=false;b.textContent='Опубликовать →'}
 });
}
async function profile(username,run){
 const u=await api('/api/profile?username='+encode(username));if(run!==generation)return;
 profileName=username;const own=username===me.username;
 content.innerHTML=`<section class="card"><div class="profile-cover"></div><div class="profile-main"><div class="profile-identity">${avatar(u.display,'xl')}<div><h1>${esc(u.display)}</h1><p>@${esc(u.username)}</p></div></div><div class="profile-action"><button class="button ${own?'secondary':''} small" ${own?'data-view="settings"':`data-message="${esc(u.username)}"`}>${own?icon('edit')+' Редактировать':icon('messages')+' Написать'}</button></div></div><div class="profile-summary"><h3>Информация</h3><dl><div class="profile-detail"><dt>О себе</dt><dd>${esc(u.bio||'Пока ничего не рассказал о себе.')}</dd></div><div class="profile-detail"><dt>ВнеКонтакта с</dt><dd>${esc(registrationDate(u.created))}</dd></div></dl></div></section><section class="card card-pad"><div class="card-title">Это ${own?'твоя страница':'страница пользователя'}</div><p class="section-description" style="margin:12px 0 0">${own?'Расскажи о себе в настройках, публикуй фотографии и общайся с друзьями.':'Напиши сообщение или посмотри публикации в общей ленте.'}</p></section>`;
}
function renderSettings(){
 content.innerHTML=`<section class="card"><div class="card-head"><div><h2 class="card-title">Редактирование страницы</h2><div class="card-subtitle">Основная информация о тебе</div></div>${icon('cog')}</div><form id="settings-form" class="form-block"><div class="field"><label for="display">Как тебя называть</label><input class="input" id="display" name="display" value="${esc(me.display)}" maxlength="60" required></div><div class="field"><label for="bio">Немного о себе</label><textarea class="textarea" id="bio" name="bio" maxlength="500" placeholder="Любимые занятия, интересы, что-нибудь ещё…">${esc(me.bio)}</textarea><div class="field-hint">Эту информацию увидят другие пользователи</div></div><div class="form-actions"><span class="muted tiny">Изменения сохраняются сразу</span><button class="button">Сохранить изменения</button></div><div class="notice" id="notice"></div></form></section><section class="card"><div class="card-head"><div><h2 class="card-title">Личные заметки</h2><div class="card-subtitle">Твои записи для себя</div></div>${icon('edit')}</div><form id="vault-form" class="form-block"><p class="section-description">Здесь можно хранить небольшой текст, который не отображается в профиле.</p><div class="field"><textarea class="textarea" name="secret" maxlength="512" rows="4" placeholder="Напиши что-нибудь личное…">${esc(me.vault)}</textarea></div><div class="form-actions"><span class="muted tiny">Не больше 512 символов</span><button class="button secondary">Сохранить заметку</button></div></form></section>`;
 qs('#settings-form').addEventListener('submit',async e=>{e.preventDefault();const b=e.submitter;b.disabled=true;try{await api('/api/settings',form(Object.fromEntries(new FormData(e.target))));me=await api('/api/me');account();toast('Настройки сохранены')}catch(err){notice(err)}finally{b.disabled=false}});
 qs('#vault-form').addEventListener('submit',async e=>{e.preventDefault();const b=e.submitter;b.disabled=true;try{await api('/api/vault/set',form(Object.fromEntries(new FormData(e.target))));me=await api('/api/me');toast('Заметка сохранена')}catch(err){notice(err)}finally{b.disabled=false}});
}

function renderMessage(m){
 return `<div class="message ${m.From===me.username?'mine':''}"><div class="message-text">${esc(m.Text)}</div><div class="message-meta">${esc(m.From)} · ${esc(m.Created)}</div></div>`;
}
function contactList(users,chosen){
 return users.map(u=>`<button class="contact-item ${u.Name===chosen?'selected':''}" data-message="${esc(u.Name)}">${avatar(u.Display)}<span><strong>${esc(u.Display)}</strong><small>@${esc(u.Name)}</small></span></button>`).join('');
}
function sessionValid(s){return s===activeThread&&view==='messages'&&generation===s.run}
function threadStatus(s,text){if(sessionValid(s)){const el=qs('#thread-status');if(el)el.textContent=text}}
function appendMessage(s,m){
 if(!sessionValid(s)||!m?.ID||s.seen.has(m.ID))return;
 if(!((m.From===me.username&&m.To===s.peer)||(m.From===s.peer&&m.To===me.username)))return;
 const thread=qs('#thread');if(!thread)return;
 const nearBottom=thread.scrollHeight-thread.scrollTop-thread.clientHeight<110;
 const empty=thread.querySelector('.empty');if(empty)empty.remove();
 thread.insertAdjacentHTML('beforeend',renderMessage(m));
 s.seen.add(m.ID);
 if(nearBottom)thread.scrollTop=thread.scrollHeight;
}
async function syncMessages(s){
 if(!sessionValid(s)||s.syncing)return;
 s.syncing=true;
 try{
  const received=await api('/api/messages?with='+encode(s.peer));
  if(!sessionValid(s))return;
  received.forEach(m=>appendMessage(s,m));
 }catch(err){if(sessionValid(s))threadStatus(s,'Не удалось обновить переписку')}
 finally{s.syncing=false}
}
function settlePending(s,clientID){
 if(!s.pending||s.pending.id!==clientID)return;
 clearTimeout(s.pendingTimer);
 const pending=s.pending;s.pending=null;
 if(pending.field.value.trim()===pending.text)pending.field.value='';
 pending.button.disabled=false;
 pending.field.focus();
}
function websocketURL(){return `${location.protocol==='https:'?'wss':'ws'}://${location.host}/api/ws`}
function connectMessages(s){
 if(!sessionValid(s))return;
 threadStatus(s,'Соединяемся…');
 let socket;
 try{socket=new WebSocket(websocketURL())}
 catch(e){threadStatus(s,'Подключение недоступно');return}
 s.socket=socket;
 socket.onopen=()=>{
  if(!sessionValid(s)){socket.close();return}
  s.retry=700;
  threadStatus(s,'');
  syncMessages(s);
 };
 socket.onmessage=e=>{
  if(!sessionValid(s))return;
  let event;try{event=JSON.parse(e.data)}catch{return}
  if(event.type==='message')appendMessage(s,event.message);
  if(event.type==='ack'){
   appendMessage(s,event.message);
   settlePending(s,event.client_id);
   refreshConversations().catch(()=>{});
  }
  if(event.type==='error'){
   if(s.pending&&s.pending.id===event.client_id){
    clearTimeout(s.pendingTimer);s.pending.button.disabled=false;s.pending=null;
   }
   toast(event.error||'Сообщение не отправлено');
  }
 };
 socket.onclose=()=>{
  if(!sessionValid(s))return;
  if(s.pending){
   clearTimeout(s.pendingTimer);s.pending.button.disabled=false;s.pending=null;
   syncMessages(s);
  }
  threadStatus(s,'Связь потеряна · переподключаемся…');
  const delay=s.retry;s.retry=Math.min(15000,Math.round(s.retry*1.8));
  s.reconnectTimer=setTimeout(()=>connectMessages(s),delay);
 };
 socket.onerror=()=>{if(sessionValid(s))threadStatus(s,'Проверяем соединение…')};
}
async function messages(selected,run){
 const users=await api('/api/conversations');
 if(run!==generation)return;
 conversationsCache=users;
 peer=selected||users[0]?.Name||'';
 let target=users.find(u=>u.Name===peer);
 if(peer&&!target){
  const p=await api('/api/profile?username='+encode(peer));if(run!==generation)return;
  target={Name:p.username,Display:p.display};
 }
 const msgs=peer?await api('/api/messages?with='+encode(peer)):[];
 if(run!==generation)return;
 content.innerHTML=`<section class="card"><div class="card-head"><h2 class="card-title">Мои сообщения</h2><span class="card-subtitle">Личная переписка</span></div><div class="message-layout"><div class="contact-column"><form id="contact-search" class="contact-search"><input class="input" name="username" placeholder="Найти по логину" aria-label="Логин собеседника" maxlength="25" required><button class="contact-find" type="submit" aria-label="Открыть диалог">→</button></form><div id="contacts">${contactList(users,peer)}</div></div><div class="thread-column">${target?`<div class="thread-head">${avatar(target.Display)}<span>${esc(target.Display)}</span><small id="thread-status">Соединяемся…</small></div><div class="thread-area" id="thread">${msgs.map(renderMessage).join('')||blank(icon('messages'),'Начни разговор','Напиши первое сообщение.')}</div><form class="message-compose" id="send-form"><input class="input" name="text" maxlength="2000" placeholder="Написать сообщение…" autocomplete="off" aria-label="Новое сообщение" required><button class="button" type="submit">${icon('send')} <span>Отправить</span></button></form>`:blank(icon('messages'),'Выбери собеседника','Начни общение с кем-нибудь из пользователей.')}</div></div></section>`;
 qs('#contact-search').addEventListener('submit',e=>{e.preventDefault();const username=new FormData(e.currentTarget).get('username').trim().toLowerCase();if(username&&username!==me.username)navigate('messages',username);else toast('Укажи логин другого пользователя')});
 const search=qs('#contact-search input');
 const list=qs('#contacts');
 function showSearchResults(){
  if(run!==generation)return;
  const query=search.value.trim().toLowerCase();
  const matches=peopleCache.filter(u=>u.Name!==me.username&&(u.Name.toLowerCase().includes(query)||u.Display.toLowerCase().includes(query)));
  list.classList.add('search-open');
  list.innerHTML=contactList(matches,peer);
 }
 function closeSearch(){
  list.classList.remove('search-open');
  list.innerHTML=contactList(conversationsCache,peer);
 }
 search.addEventListener('focus',async()=>{
  showSearchResults();
  try{await refreshPeople();if(document.activeElement===search)showSearchResults()}
  catch(err){toast(err.message)}
 });
 search.addEventListener('input',showSearchResults);
 search.addEventListener('keydown',e=>{if(e.key==='Escape'){search.blur();closeSearch()}});
 qs('.thread-column').addEventListener('pointerdown',closeSearch);
 if(!target)return;
 const thread=qs('#thread');thread.scrollTop=thread.scrollHeight;
 const s={run,peer,seen:new Set(msgs.map(m=>m.ID)),socket:null,reconnectTimer:null,pendingTimer:null,pending:null,syncing:false,retry:700};
 activeThread=s;
 connectMessages(s);
 const send=qs('#send-form');send.addEventListener('submit',async e=>{
  e.preventDefault();
  const field=send.querySelector('input[name="text"]'),text=field.value.trim();if(!text||s.pending)return;
  const button=send.querySelector('button[type="submit"]');
  if(s.socket&&s.socket.readyState===WebSocket.OPEN){
   const id=Date.now().toString(36)+'-'+Math.random().toString(36).slice(2);
   s.pending={id,text,field,button};button.disabled=true;
   try{s.socket.send(JSON.stringify({type:'send',to:s.peer,text,client_id:id}))}
   catch(err){s.pending=null;button.disabled=false;toast('Сообщение не отправлено');return}
   s.pendingTimer=setTimeout(()=>{
    if(!sessionValid(s)||!s.pending||s.pending.id!==id)return;
    s.pending=null;button.disabled=false;
    syncMessages(s);
    toast('Нет подтверждения отправки. Проверь переписку перед повтором.');
   },8500);
   return;
  }
  button.disabled=true;
  try{
   await api('/api/messages',form({to:s.peer,text}));
   if(sessionValid(s)){
    if(field.value.trim()===text)field.value='';
    await syncMessages(s);refreshConversations().catch(()=>{});thread.scrollTop=thread.scrollHeight;field.focus();
   }
  }catch(err){if(sessionValid(s))toast(err.message)}finally{button.disabled=false}
 });
}

document.addEventListener('click',e=>{
 const auth=e.target.closest('[data-auth]');if(auth){showAuth(auth.dataset.auth);return}
 const like=e.target.closest('[data-like]');if(like){toggleLike(like);return}
 const user=e.target.closest('[data-user]');if(user){navigate('profile',user.dataset.user);return}
 const message=e.target.closest('[data-message]');if(message){navigate('messages',message.dataset.message);return}
 const viewButton=e.target.closest('[data-view]');if(viewButton){e.preventDefault();if(me)navigate(viewButton.dataset.view);return}
 if(e.target.closest('#logout'))logout();
});
document.addEventListener('visibilitychange',()=>{if(!document.hidden&&activeThread)syncMessages(activeThread)});
boot();
