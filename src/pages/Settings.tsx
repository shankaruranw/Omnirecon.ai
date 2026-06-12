import { useState } from "react";
import * as Icons from "lucide-react";
import { getCurrentUser, updateProfile, changePassword, getPrefs, setPrefs, logout } from "../lib/auth";
import { getHistory, clearHistory, getReports, clearReports } from "../lib/history";
import { Card, Button, Input, Badge } from "../lib/ui";
import { useToast } from "../lib/toast";
import { getTheme, toggleTheme, type Theme } from "../lib/theme";

export default function Settings() {
  const toast = useToast();
  const user = getCurrentUser();
  const [name, setName]             = useState(user?.name || "");
  const [oldPw, setOldPw]           = useState("");
  const [newPw, setNewPw]           = useState("");
  const [prefs, setLocalPrefs]      = useState(getPrefs());
  const [theme, setThemeState]      = useState<Theme>(getTheme());

  const saveName = () => { const r=updateProfile(name); r.ok?toast("Profile updated."):toast(r.error||"Failed.","error"); };
  const savePw   = () => { const r=changePassword(oldPw,newPw); if(r.ok){toast("Password changed.");setOldPw("");setNewPw("");}else toast(r.error||"Failed.","error"); };
  const updatePref = (patch: any) => { const m=setPrefs(patch); setLocalPrefs(m); toast("Preferences saved.","info"); };
  const exportAll = () => { const data={user,prefs:getPrefs(),scans:getHistory(),reports:getReports()}; const a=document.createElement("a"); a.href=URL.createObjectURL(new Blob([JSON.stringify(data,null,2)],{type:"application/json"})); a.download=`omnirecon-backup-${Date.now()}.json`; a.click(); toast("Backup exported."); };

  const handleTheme = () => { const next=toggleTheme(); setThemeState(next); toast(`Switched to ${next} mode`,"info"); };
  return (
    <div className="fade-in mx-auto max-w-3xl space-y-5">
      <div><h1 className="text-2xl font-bold text-slate-100">Settings</h1><p className="text-sm text-slate-400">Manage your profile, security and preferences.</p></div>
      <Card className="p-5">
        <div className="mb-4 flex items-center gap-2 text-slate-100"><Icons.UserCog className="h-5 w-5 text-teal-400"/><h3 className="font-semibold">Profile</h3></div>
        <div className="flex items-center gap-4 mb-4">
          <div className="flex h-14 w-14 items-center justify-center rounded-xl bg-teal-500 text-2xl font-bold text-slate-950">{(user?.name||user?.email||"U").slice(0,1).toUpperCase()}</div>
          <div><div className="text-sm font-semibold text-slate-100">{user?.name}</div><div className="text-xs text-slate-500">{user?.email}</div></div>
        </div>
        <div><label className="mb-1 block text-xs font-medium text-slate-400">Display Name</label><div className="flex gap-2"><Input value={name} onChange={e=>setName(e.target.value)}/><Button onClick={saveName}>Save</Button></div></div>
      </Card>
      <Card className="p-5">
        <div className="mb-4 flex items-center gap-2 text-slate-100"><Icons.ShieldCheck className="h-5 w-5 text-teal-400"/><h3 className="font-semibold">Security</h3></div>
        <div className="grid gap-3 sm:grid-cols-2">
          <div><label className="mb-1 block text-xs font-medium text-slate-400">Current Password</label><Input type="password" value={oldPw} onChange={e=>setOldPw(e.target.value)} placeholder="••••••••"/></div>
          <div><label className="mb-1 block text-xs font-medium text-slate-400">New Password</label><Input type="password" value={newPw} onChange={e=>setNewPw(e.target.value)} placeholder="min 6 chars"/></div>
        </div>
        <Button className="mt-3" onClick={savePw} disabled={!oldPw||!newPw}>Change Password</Button>
      </Card>
      <Card className="p-5">
        <div className="mb-4 flex items-center gap-2 text-slate-100"><Icons.SlidersHorizontal className="h-5 w-5 text-teal-400"/><h3 className="font-semibold">Preferences</h3></div>
        <div className="space-y-4">

          {/* ── Theme Toggle ── */}
          <div className="flex items-center justify-between">
            <div>
              <div className="text-sm font-semibold text-slate-200">Interface Theme</div>
              <div className="text-xs text-slate-500">
                Currently: <span className="font-semibold text-teal-400">{theme === "dark" ? "🌙 Dark Mode" : "☀️ Light Mode"}</span>
              </div>
            </div>
            <button
              onClick={handleTheme}
              className={`flex items-center gap-2 rounded-lg border px-4 py-2 text-sm font-semibold transition
                ${theme === "dark"
                  ? "border-teal-500/40 bg-teal-500/10 text-teal-300 hover:bg-teal-500/20"
                  : "border-amber-500/40 bg-amber-500/10 text-amber-600 hover:bg-amber-500/20"
                }`}
            >
              {theme === "dark"
                ? <><Icons.Sun className="h-4 w-4"/> Switch to Light</>
                : <><Icons.Moon className="h-4 w-4"/> Switch to Dark</>
              }
            </button>
          </div>

          {/* Visual preview cards */}
          <div className="grid grid-cols-2 gap-3">
            <button onClick={()=>{ if(theme!=="dark"){handleTheme();} }}
              className={`rounded-xl border-2 p-4 text-left transition ${theme==="dark"?"border-teal-500 bg-slate-900":"border-slate-300 bg-slate-100 opacity-60"}`}>
              <div className="mb-2 flex h-8 w-full items-center gap-1 rounded-md bg-slate-950 px-2">
                <span className="h-2 w-2 rounded-full bg-rose-500"/><span className="h-2 w-2 rounded-full bg-amber-500"/><span className="h-2 w-2 rounded-full bg-emerald-500"/>
              </div>
              <div className="space-y-1">
                <div className="h-2 w-3/4 rounded bg-slate-700"/>
                <div className="h-2 w-1/2 rounded bg-slate-800"/>
              </div>
              <div className="mt-2 text-xs font-bold text-slate-300">🌙 Dark Mode</div>
              {theme==="dark"&&<div className="mt-1 text-[10px] font-semibold text-teal-400">✓ Active</div>}
            </button>
            <button onClick={()=>{ if(theme!=="light"){handleTheme();} }}
              className={`rounded-xl border-2 p-4 text-left transition ${theme==="light"?"border-teal-500 bg-white":"border-slate-700 bg-slate-800 opacity-60"}`}>
              <div className="mb-2 flex h-8 w-full items-center gap-1 rounded-md bg-slate-200 px-2">
                <span className="h-2 w-2 rounded-full bg-rose-400"/><span className="h-2 w-2 rounded-full bg-amber-400"/><span className="h-2 w-2 rounded-full bg-emerald-400"/>
              </div>
              <div className="space-y-1">
                <div className="h-2 w-3/4 rounded bg-slate-300"/>
                <div className="h-2 w-1/2 rounded bg-slate-200"/>
              </div>
              <div className="mt-2 text-xs font-bold text-slate-600">☀️ Light Mode</div>
              {theme==="light"&&<div className="mt-1 text-[10px] font-semibold text-teal-600">✓ Active</div>}
            </button>
          </div>

          {/* Animations toggle */}
          <div className="flex items-center justify-between">
            <div><div className="text-sm text-slate-200">Animations</div><div className="text-xs text-slate-500">Enable fade & motion effects.</div></div>
            <button onClick={()=>updatePref({animations:!prefs.animations})} className={`relative h-6 w-11 rounded-full transition ${prefs.animations?"bg-teal-500":"bg-slate-700"}`}>
              <span className={`absolute top-0.5 h-5 w-5 rounded-full bg-white transition-all ${prefs.animations?"left-[22px]":"left-0.5"}`}/>
            </button>
          </div>
        </div>
      </Card>
      <Card className="p-5">
        <div className="mb-4 flex items-center gap-2 text-slate-100"><Icons.Database className="h-5 w-5 text-teal-400"/><h3 className="font-semibold">Data Management</h3></div>
        <div className="mb-3 flex flex-wrap gap-3 text-sm"><Badge color="teal">{getHistory().length} scans</Badge><Badge color="indigo">{getReports().length} reports</Badge></div>
        <div className="flex flex-wrap gap-2">
          <Button variant="ghost" onClick={exportAll}><Icons.Download className="h-4 w-4"/>Export Backup</Button>
          <Button variant="ghost" onClick={()=>{clearHistory();toast("Scans cleared.","info")}}><Icons.Trash2 className="h-4 w-4"/>Clear Scans</Button>
          <Button variant="ghost" onClick={()=>{clearReports();toast("Reports cleared.","info")}}><Icons.Trash2 className="h-4 w-4"/>Clear Reports</Button>
          <Button variant="danger" onClick={()=>{if(confirm("Sign out?"))logout()}}><Icons.LogOut className="h-4 w-4"/>Sign Out</Button>
        </div>
      </Card>
    </div>
  );
}
