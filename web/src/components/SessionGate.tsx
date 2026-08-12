import { useState } from 'react';
import { Alert, Button, Form, Input, Space, Tag, Typography } from '@arco-design/web-react';
import { IconBranch, IconCloud, IconLock, IconRight, IconSafe, IconThunderbolt } from '@arco-design/web-react/icon';
import { createSession, isSessionExpired } from '../session';
import type { Session } from '../types';

type Props = {
  onConnect: (session: Session) => void;
};

export function SessionGate({ onConnect }: Props) {
  const [token, setToken] = useState('');
  const [error, setError] = useState<string | null>(null);

  const connect = () => {
    try {
      const session = createSession(token);
      if (isSessionExpired(session)) throw new Error('JWT 已过期，请获取新的管理会话');
      setError(null);
      onConnect(session);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : '无法建立管理会话');
    }
  };

  return (
    <main className="session-shell">
      <section className="session-panel" aria-label="连接 Candy Cloud">
        <div className="session-brand">
          <div className="brand-mark">C</div>
          <div>
            <Typography.Title heading={3}>Candy Cloud</Typography.Title>
            <Typography.Text type="secondary">SD-WAN 管理控制台</Typography.Text>
          </div>
        </div>
        <div className="session-heading">
          <Tag color="arcoblue" icon={<IconLock />}>管理会话</Tag>
          <Typography.Title heading={4}>连接控制面</Typography.Title>
          <Typography.Paragraph type="secondary">
            使用由身份系统签发的管理 JWT。会话只保存在当前浏览器标签页中。
          </Typography.Paragraph>
        </div>
        {error && <Alert type="error" content={error} showIcon />}
        <Form layout="vertical" className="session-form">
          <Form.Item label="管理 JWT" required>
            <Input.TextArea
              value={token}
              onChange={setToken}
              autoSize={{ minRows: 5, maxRows: 9 }}
              placeholder="eyJ..."
              onKeyDown={(event) => {
                if ((event.metaKey || event.ctrlKey) && event.key === 'Enter') connect();
              }}
            />
          </Form.Item>
          <Button type="primary" long size="large" icon={<IconRight />} onClick={connect} disabled={!token.trim()}>
            建立会话
          </Button>
        </Form>
        <Space className="session-footnote" size={6}>
          <span className="secure-dot" />
          <Typography.Text type="secondary">凭据仅保留在 sessionStorage</Typography.Text>
        </Space>
      </section>
      <aside className="session-context" aria-label="Candy Cloud 控制面能力">
        <div className="session-context-head">
          <Tag color="arcoblue">CLOUD 0.1</Tag>
          <Typography.Title heading={2}>站点、路径与出口，统一编排。</Typography.Title>
          <Typography.Paragraph>Cloud 只管理控制意图与签名投影，不进入客户数据面转发路径。</Typography.Paragraph>
        </div>
        <div className="session-capabilities">
          <div><IconBranch /><strong>多站点互联</strong><span>全双工 TUN 与站点网段管理</span></div>
          <div><IconThunderbolt /><strong>路径与出口</strong><span>直连、Relay 与远端 Candy 出口</span></div>
          <div><IconSafe /><strong>签名同步</strong><span>mTLS 身份、ETag 与原子应用</span></div>
        </div>
        <div className="session-core-line"><IconCloud /><span>Candy Core 0.3.10 · Wire 0.3</span></div>
      </aside>
    </main>
  );
}
