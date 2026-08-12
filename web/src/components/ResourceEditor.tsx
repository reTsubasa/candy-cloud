import { useEffect, useState } from 'react';
import { Alert, Button, Drawer, Form, Input, Space, Typography } from '@arco-design/web-react';
import { IconCode, IconSave } from '@arco-design/web-react/icon';
import { createResource, replaceResource } from '../api';
import { defaultSpec } from '../resource-definitions';
import type { ControlResource, ResourceDefinition, ResourceSpec, Session } from '../types';

type Props = {
  visible: boolean;
  definition: ResourceDefinition;
  session: Session;
  resource: ControlResource | null;
  onClose: () => void;
  onSaved: (resource: ControlResource) => void;
};

export function ResourceEditor({ visible, definition, session, resource, onClose, onSaved }: Props) {
  const [value, setValue] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    const spec = resource?.resource ?? defaultSpec(definition.kind);
    setValue(JSON.stringify(spec, null, 2));
    setError(null);
  }, [definition.kind, resource, visible]);

  const save = async () => {
    let spec: ResourceSpec;
    try {
      spec = JSON.parse(value) as ResourceSpec;
      if (!spec || spec.kind !== definition.kind || typeof spec.spec !== 'object' || spec.spec === null) {
        throw new Error(`资源必须包含 kind: "${definition.kind}" 和 spec 对象`);
      }
    } catch (reason) {
      setError(reason instanceof SyntaxError ? `JSON 格式错误：${reason.message}` : String(reason instanceof Error ? reason.message : reason));
      return;
    }
    const tenantId = session.claims.tenant_id;
    if (!tenantId) {
      setError('JWT 中没有 tenant_id，无法确定管理资源范围');
      return;
    }
    setSaving(true);
    setError(null);
    try {
      const response = resource
        ? await replaceResource(session.token, tenantId, definition.collection, resource.metadata.id, resource.metadata.revision, spec)
        : await createResource(session.token, tenantId, definition.collection, spec);
      onSaved(response.resource);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : '保存失败');
    } finally {
      setSaving(false);
    }
  };

  return (
    <Drawer
      width={560}
      visible={visible}
      onCancel={onClose}
      title={resource ? `编辑${definition.label}` : `新建${definition.label}`}
      footer={
        <Space>
          <Button onClick={onClose}>取消</Button>
          <Button type="primary" icon={<IconSave />} loading={saving} onClick={save}>保存</Button>
        </Space>
      }
    >
      <div className="editor-intro">
        <IconCode />
        <div>
          <Typography.Text bold>V1 资源定义</Typography.Text>
          <Typography.Paragraph type="secondary">
            字段将按后端严格契约校验。更新使用 revision {resource?.metadata.revision ?? 1} 进行并发保护。
          </Typography.Paragraph>
        </div>
      </div>
      {error && <Alert type="error" content={error} showIcon className="editor-alert" />}
      <Form layout="vertical">
        <Form.Item label="资源 JSON" required>
          <Input.TextArea
            className="json-editor"
            value={value}
            onChange={setValue}
            spellCheck={false}
            autoSize={{ minRows: 19, maxRows: 30 }}
          />
        </Form.Item>
      </Form>
    </Drawer>
  );
}
