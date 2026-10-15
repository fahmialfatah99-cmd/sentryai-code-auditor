import '../styles/globals.css';

export const metadata = {
  title: 'SentryAI - Real-Time Code Auditor',
  description: 'AST-based security audit with Shannon-entropy secret detection and patch suggestions.'
};

export default function RootLayout({ children }) {
  return (
    <html lang="en">
      <body className="bg-[#0a0d14] text-slate-100 min-h-screen antialiased selection:bg-cyan-500 selection:text-black">
        {children}
      </body>
    </html>
  );
}
