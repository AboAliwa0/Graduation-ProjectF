(function(){
  if(document.querySelector('.ai-assistant'))return;
  var root=document.createElement('div');root.className='ai-assistant';
  root.innerHTML='<section class="ai-panel" role="dialog" aria-label="CyberScan AI Assistant"><header class="ai-head"><div><strong>CyberScan Assistant</strong><small>Secure platform guide</small></div><button class="ai-close" aria-label="Close assistant">×</button></header><div class="ai-messages" aria-live="polite"><div class="ai-message bot">Hi! Ask me about any CyberScan feature or web-security concept in English or Arabic. Never share passwords, tokens, or private data.</div><div class="ai-actions ai-prompts"><button type="button" data-question="How do I start a new scan?">Start a scan</button><button type="button" data-question="What is the difference between scan modes?">Scan modes</button><button type="button" data-question="How do I use the Learning Center?">Learning Center</button></div></div><form class="ai-form"><input class="ai-input" maxlength="800" placeholder="Ask how to use CyberScan…" aria-label="Ask the assistant" required><button class="ai-send" type="submit">Send</button></form></section><button class="ai-launcher" aria-label="Open AI assistant">AI</button>';
  document.body.appendChild(root);
  var messages=root.querySelector('.ai-messages'),input=root.querySelector('.ai-input'),send=root.querySelector('.ai-send');
  function add(text,type,actions){var box=document.createElement('div');box.className='ai-message '+type;box.textContent=text;if(actions&&actions.length){var links=document.createElement('div');links.className='ai-actions';actions.forEach(function(action){var a=document.createElement('a');a.href=action.url;a.textContent=action.label;links.appendChild(a)});box.appendChild(links)}messages.appendChild(box);messages.scrollTop=messages.scrollHeight}
  root.querySelector('.ai-launcher').onclick=function(){root.classList.toggle('open');if(root.classList.contains('open'))input.focus()};
  root.querySelector('.ai-close').onclick=function(){root.classList.remove('open')};
  async function ask(question){
    if(!question)return;
    var privatePattern=/(password|passwd|secret|api[_ -]?key|access[_ -]?token|refresh[_ -]?token|authorization|cookie|session)\s*[:=]|bearer\s+[a-z0-9._~+/=-]{8,}/i;
    if(privatePattern.test(question)){input.value='';add('For your protection, this message was not sent because it appears to contain sensitive data. Remove the secret value and ask in general terms.','bot');return;}
    add(question,'user');input.value='';send.disabled=true;
    try{var response=await fetch('/api/assistant',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({message:question,page:location.pathname})});var data=await response.json();add(data.answer||data.error||'I could not answer that question.','bot',data.actions)}catch(error){add('The assistant is temporarily unavailable. Please try again.','bot')}finally{send.disabled=false;input.focus()}
  }
  root.querySelector('.ai-prompts').addEventListener('click',function(event){var button=event.target.closest('[data-question]');if(button)ask(button.dataset.question)});
  root.querySelector('form').addEventListener('submit',function(event){event.preventDefault();ask(input.value.trim())});
})();
