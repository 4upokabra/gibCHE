import { Shield, Zap } from "lucide-react";
import { PendingAction } from "../types";

type AuthOverlayProps = {
  isAuthorized: boolean;
  passwordInput: string;
  onChangePassword: (value: string) => void;
  onSubmit: () => void;
  authError: string;
  pendingAction: PendingAction;
};

export function AuthOverlay({
  isAuthorized,
  passwordInput,
  onChangePassword,
  onSubmit,
  authError,
  pendingAction,
}: AuthOverlayProps) {
  if (isAuthorized) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-950/95 px-4">
      <div className="shimmer-border surface z-50 w-full max-w-md space-y-6 p-8 text-center">
        <Shield className="mx-auto h-10 w-10 text-primary" />
        <div>
          <p className="text-xs uppercase tracking-[0.4em] text-slate-400">Доступ ограничен</p>
          <h2 className="mt-2 text-2xl font-semibold text-white">Введите пароль доступа</h2>
          <p className="text-sm text-slate-400">Переменная окружения VITE_ACCESS_PASS задаёт пароль.</p>
        </div>
        <input
          type="password"
          className="w-full rounded-2xl border border-white/10 bg-white/5 px-4 py-3 text-sm text-white placeholder:text-slate-500 focus:border-primary/60 focus:outline-none focus:ring-2 focus:ring-primary/20"
          placeholder="Пароль"
          value={passwordInput}
          onChange={(e) => onChangePassword(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && onSubmit()}
        />
        <button
          onClick={onSubmit}
          disabled={pendingAction !== null}
          className="inline-flex w-full items-center justify-center gap-2 rounded-2xl bg-gradient-to-r from-primary to-accent px-6 py-3 font-semibold text-slate-950 shadow-primary/40 transition hover:brightness-110 disabled:opacity-60"
        >
          <Zap className="h-4 w-4" />
          Войти
        </button>
        {authError && <p className="text-xs text-rose-300">{authError}</p>}
      </div>
    </div>
  );
}


