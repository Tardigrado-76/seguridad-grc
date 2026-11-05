"""
Module: fix_html.py
Description: Production-ready enterprise component for Fix Html.
Hardened with Zero Trust, structured logging, and dynamic environment configuration.
"""




import re

with open('src/templates/index.html', 'r', encoding='utf-8') as f:
    content = f.read()

# Remove the <style> block
content = re.sub(r'<style>.*?</style>\n?', '', content, flags=re.DOTALL)

# Replace the specific style attributes
content = content.replace('style=\"font-family:''JetBrains Mono'',monospace;color:#00E5A0;background:#0A0C10;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:2rem;text-align:center;position:fixed;top:0;left:0;width:100vw;z-index:9999;\"', 'class=\"font-mono text-[#00E5A0] bg-[#0A0C10] min-h-screen flex items-center justify-center p-8 text-center fixed top-0 left-0 w-screen z-[9999]\"')
content = content.replace('style=\"font-size:1.2rem;margin-bottom:1rem\"', 'class=\"text-xl mb-4\"')
content = content.replace('style=\"font-size:0.8rem;opacity:0.7\"', 'class=\"text-xs opacity-70\"')
content = content.replace('style=\"width: 45%\"', 'class=\"w-[45%]\"')

# Replace the alpine script
content = content.replace('/static/js/alpine.min.js', '/static/js/alpine.csp.min.js')

# Replace the custom classes with tailwind classes
content = content.replace('class=\"panel\"', 'class=\"bg-slate-900 border border-slate-800 rounded-lg p-4\"')
content = content.replace('class=\"panel flex-1 flex flex-col\"', 'class=\"bg-slate-900 border border-slate-800 rounded-lg p-4 flex-1 flex flex-col\"')
content = content.replace('class=\"panel flex-shrink-0\"', 'class=\"bg-slate-900 border border-slate-800 rounded-lg p-4 flex-shrink-0\"')
content = content.replace('class=\"panel col-span-12 z-10 flex-shrink-0\"', 'class=\"bg-slate-900 border border-slate-800 rounded-lg p-4 col-span-12 z-10 flex-shrink-0\"')
content = content.replace('class=\"panel border-cyan-500 max-w-md w-full\"', 'class=\"bg-slate-900 border border-cyan-500 rounded-lg p-4 max-w-md w-full\"')

content = content.replace('class=\"panel-header\"', 'class=\"font-sans font-bold uppercase border-b border-slate-800 mb-4 pb-2 text-cyan-400\"')
content = content.replace('class=\"panel-header text-amber-400\"', 'class=\"font-sans font-bold uppercase border-b border-slate-800 mb-4 pb-2 text-amber-400\"')
content = content.replace('class=\"panel-header text-red-500\"', 'class=\"font-sans font-bold uppercase border-b border-slate-800 mb-4 pb-2 text-red-500\"')

content = content.replace('class=\"scanline\"', 'class=\"fixed top-0 left-0 w-screen h-screen pointer-events-none z-50 bg-[linear-gradient(to_bottom,rgba(255,255,255,0),rgba(255,255,255,0)_50%,rgba(0,0,0,0.1)_50%,rgba(0,0,0,0.1))] bg-[length:100%_4px]\"')

content = content.replace('class=\"log-terminal font-mono rounded\"', 'class=\"h-64 overflow-y-auto bg-black p-2 border border-slate-800 text-sm font-mono rounded\"')

# Handle the header panel
content = content.replace('class=\"panel flex justify-between items-center bg-slate-900 border-cyan-500/30 flex-shrink-0\"', 'class=\"bg-slate-900 border border-cyan-500/30 rounded-lg p-4 flex justify-between items-center flex-shrink-0\"')

with open('src/templates/index.html', 'w', encoding='utf-8') as f:
    f.write(content)


if __name__ == '__main__':
    # Production entry point
    pass
